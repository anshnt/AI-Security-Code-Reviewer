import { parsePatch, reconstructFromPatch } from '../analysis/diff';
import { buildTarget, scan, type FileInput } from '../analysis/engine';
import { SEVERITY_RANK, type Finding, type ScanTarget, type Severity } from '../analysis/types';
import { triage, type TriagedFinding } from '../ai/triage';
import type { AppConfig } from '../config';
import { mergeRepoConfig } from '../config/merge';
import { CONFIG_PATHS, emptyRepoConfig, parseRepoConfig, pathInScope, type RepoConfig } from '../config/repo-config';
import type { ReviewStore } from '../storage/database';
import { logger } from '../util/logger';
import { COMMENT_MARKER, renderComment, renderStatusDescription, type TriageSummary } from './comment';
import type { GitHubClient, PullRequestFile } from './client';
import { planInlineComments } from './inline';
import { renderSarif } from '../report/sarif';

/**
 * End-to-end review of one pull request.
 *
 * The sequence is deliberately linear and idempotent: a re-run on the same head
 * SHA produces the same comment and the same status, which matters because
 * GitHub redelivers webhooks and because authors push repeatedly.
 */

/** Identity reported to code scanning, so alerts are attributed to this tool. */
export const TOOL_NAME = 'security-review';
export const TOOL_VERSION = '0.1.0';
export const TOOL_URI = 'https://github.com/anshnt/AI-Security-Code-Reviewer';

export interface ReviewRequest {
  owner: string;
  repo: string;
  pullNumber: number;
}

export interface ReviewOutcome {
  scanId: number;
  findings: TriagedFinding[];
  filesScanned: number;
  newFindings: number;
  resolvedFindings: number;
  status: 'success' | 'failure';
  skipped?: string;
  /** How many findings the triage pass judged, and how many it refuted. */
  triaged?: number;
  refuted?: number;
  /** How many findings were anchored to their line in the diff. */
  inlineComments?: number;
  /** Problems found in the repository's own config file. */
  configWarnings?: string[];
  /** Set when a SARIF run was accepted by code scanning. */
  codeScanningUploadId?: string;
}

export class PullRequestReviewer {
  constructor(
    private readonly client: GitHubClient,
    private readonly store: ReviewStore,
    private readonly config: AppConfig,
  ) {}

  async review(request: ReviewRequest): Promise<ReviewOutcome> {
    const { owner, repo, pullNumber } = request;
    const repositoryFullName = `${owner}/${repo}`;
    const started = Date.now();

    const pullRequest = await this.client.pullRequest(owner, repo, pullNumber);
    logger.info('reviewing pull request', {
      repository: repositoryFullName,
      pullNumber,
      headSha: pullRequest.headSha,
      changedFiles: pullRequest.changedFiles,
    });

    // The repository's own settings, read from the base branch. See
    // `repo-config.ts` for why the head is never trusted for this.
    const repoConfig = await this.loadRepoConfig(owner, repo, pullRequest.baseSha);
    const merged = mergeRepoConfig(this.config, repoConfig);
    const config = merged.config;
    if (merged.warnings.length > 0) {
      logger.warn('repository config warnings', {
        repository: repositoryFullName,
        warnings: merged.warnings,
      });
    }

    if (pullRequest.changedFiles > config.review.maxFilesPerPullRequest) {
      const reason =
        `pull request touches ${pullRequest.changedFiles} files, above the ` +
        `${config.review.maxFilesPerPullRequest}-file limit`;
      await this.client.setCommitStatus(
        owner,
        repo,
        pullRequest.headSha,
        'success',
        'Skipped: pull request too large to review',
        this.dashboardUrl(repositoryFullName),
      );
      logger.warn('skipping oversized pull request', { repository: repositoryFullName, pullNumber });
      return {
        scanId: -1,
        findings: [],
        filesScanned: 0,
        newFindings: 0,
        resolvedFindings: 0,
        status: 'success',
        skipped: reason,
      };
    }

    await this.client.setCommitStatus(
      owner,
      repo,
      pullRequest.headSha,
      'pending',
      'Security review in progress',
      this.dashboardUrl(repositoryFullName),
    );

    const files = await this.client.pullRequestFiles(owner, repo, pullNumber);
    const commentableLines = collectCommentableLines(files);
    const inputs = (await this.buildInputs(owner, repo, pullRequest.headSha, files, config)).filter(
      (input) => pathInScope(repoConfig, input.filePath),
    );

    const summary = scan(inputs, {
      minSeverity: config.review.minSeverity,
      maxFindingsPerFile: config.review.maxFindingsPerFile,
      includeTests: config.review.includeTests,
      disabledRules: config.review.disabledRules,
    });

    // Per-rule severity replacement happens after the analyzers run, so a rule
    // can be downgraded without being silenced.
    const rescored = applySeverityOverrides(summary.findings, repoConfig);

    // Model-assisted triage refines what the analyzers found. It runs after the
    // deterministic pass and can never take its place: any failure here leaves
    // the findings exactly as the analyzers produced them.
    const reviewed = await this.applyTriage(rescored, inputs, config);

    const previouslyOpen = this.store.openFingerprints(repositoryFullName);

    const record = this.store.recordScan({
      repositoryFullName,
      pullRequestNumber: pullNumber,
      headSha: pullRequest.headSha,
      baseSha: pullRequest.baseSha,
      title: pullRequest.title,
      author: pullRequest.author,
      filesScanned: summary.filesScanned,
      durationMs: summary.durationMs,
      findings: reviewed.findings.map((finding) => ({
        ...finding,
        ...(finding.triage
          ? {
              triage: {
                verdict: finding.triage.verdict,
                confidence: finding.triage.confidence,
                model: finding.triage.model,
              },
            }
          : {}),
      })),
      examined: inputs.map((input) => ({
        path: input.filePath,
        lines: input.changedLines === null ? null : [...input.changedLines],
      })),
    });

    const newFingerprints = new Set(
      reviewed.findings
        .filter((finding) => !previouslyOpen.has(finding.fingerprint))
        .map((finding) => finding.fingerprint),
    );

    const bodyFor = (inlineCount: number): string =>
      renderComment(reviewed.findings, {
        repositoryFullName,
        headSha: pullRequest.headSha,
        filesScanned: summary.filesScanned,
        durationMs: summary.durationMs,
        newFingerprints,
        resolvedCount: record.resolvedFingerprints.length,
        maxRendered: config.review.maxFindingsPerComment,
        dashboardUrl: config.publicUrl,
        failOnSeverity: config.review.failOnSeverity,
        triage: reviewed.summary,
        inlineCommentCount: inlineCount,
        configWarnings: merged.warnings,
      });

    // Inline comments first: the summary then knows what it still has to carry.
    const inline = await this.postInlineComments(
      owner,
      repo,
      pullNumber,
      pullRequest.headSha,
      reviewed.findings,
      commentableLines,
      config,
    );

    // Code scanning is where findings become durable: GitHub tracks each alert
    // across pushes and remembers a dismissal, which a pull-request comment
    // cannot do.
    const uploadId = await this.uploadToCodeScanning(
      owner,
      repo,
      pullNumber,
      pullRequest.headSha,
      reviewed.findings,
      config,
    );

    const comment = await this.client.upsertComment(
      owner,
      repo,
      pullNumber,
      COMMENT_MARKER,
      bodyFor(inline),
    );

    const blocking = this.blockingCount(reviewed.findings, config);
    const status: 'success' | 'failure' = blocking > 0 ? 'failure' : 'success';
    await this.client.setCommitStatus(
      owner,
      repo,
      pullRequest.headSha,
      status,
      renderStatusDescription(reviewed.findings, config.review.failOnSeverity),
      this.dashboardUrl(repositoryFullName),
    );

    logger.info('review complete', {
      repository: repositoryFullName,
      pullNumber,
      findings: reviewed.findings.length,
      newFindings: newFingerprints.size,
      resolved: record.resolvedFingerprints.length,
      blocking,
      inlineComments: inline,
      commentUpdated: comment.updated,
      totalMs: Date.now() - started,
    });

    return {
      scanId: record.scanId,
      findings: reviewed.findings,
      filesScanned: summary.filesScanned,
      newFindings: newFingerprints.size,
      resolvedFindings: record.resolvedFingerprints.length,
      status,
      ...(reviewed.summary
        ? { triaged: reviewed.summary.triagedCount, refuted: reviewed.summary.refutedCount }
        : {}),
      inlineComments: inline,
      ...(merged.warnings.length > 0 ? { configWarnings: merged.warnings } : {}),
      ...(uploadId ? { codeScanningUploadId: uploadId } : {}),
    };
  }

  /**
   * Uploads a SARIF run for this pull request.
   *
   * Best effort, like the inline comments: the pull-request comment and the
   * commit status are the contract, and this is an addition on top. A repository
   * without code scanning enabled, or a token without `security_events`, is a
   * configuration fact rather than a failure.
   *
   * The ref is `refs/pull/<n>/merge` so GitHub attaches the alerts to the pull
   * request rather than to a branch that may not exist on the upstream.
   */
  private async uploadToCodeScanning(
    owner: string,
    repo: string,
    pullNumber: number,
    headSha: string,
    findings: TriagedFinding[],
    config: AppConfig,
  ): Promise<string | null> {
    if (!config.review.codeScanningUpload) return null;

    try {
      const sarif = renderSarif(findings, {
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        informationUri: TOOL_URI,
        automationId: `security-review/pr-${pullNumber}`,
      });
      const uploadId = await this.client.uploadSarif(
        owner,
        repo,
        headSha,
        `refs/pull/${pullNumber}/merge`,
        sarif,
        TOOL_NAME,
      );
      if (uploadId) {
        logger.info('uploaded sarif run', {
          repository: `${owner}/${repo}`,
          pullNumber,
          findings: findings.length,
          uploadId,
        });
      }
      return uploadId;
    } catch (error) {
      logger.warn('sarif upload failed', {
        repository: `${owner}/${repo}`,
        pullNumber,
        error: (error as Error).message,
      });
      return null;
    }
  }

  /**
   * Reads the repository's config file from the base branch.
   *
   * Deliberately the base and not the head: a config file on the head is
   * proposed, not agreed. Reading it would let a pull request disable the
   * analyzer that is about to review it - `rules: { disable: [secrets] }` in the
   * same commit that adds the credential. Requiring a merge means requiring a
   * review, which is the whole point of the mechanism.
   */
  private async loadRepoConfig(owner: string, repo: string, baseRef: string): Promise<RepoConfig> {
    for (const path of CONFIG_PATHS) {
      let text: string | null;
      try {
        text = await this.client.fileContent(owner, repo, path, baseRef, 64_000);
      } catch (error) {
        logger.warn('could not read repository config', { path, error: (error as Error).message });
        return emptyRepoConfig();
      }
      if (text === null) continue;
      const parsed = parseRepoConfig(text, path);
      logger.info('loaded repository config', {
        path,
        warnings: parsed.warnings.length,
        disabledRules: parsed.disabledRules.length,
      });
      return parsed;
    }
    return emptyRepoConfig();
  }

  /**
   * Anchors findings to their lines in the diff.
   *
   * Best effort by design: a failure here is cosmetic, because every finding is
   * in the summary comment regardless. So a rejected review or an API error is
   * logged and swallowed rather than failing the review.
   */
  private async postInlineComments(
    owner: string,
    repo: string,
    pullNumber: number,
    headSha: string,
    findings: TriagedFinding[],
    commentableLines: Map<string, Set<number>>,
    config: AppConfig,
  ): Promise<number> {
    if (!config.review.inlineComments || findings.length === 0) return 0;

    try {
      const existing = await this.client.listReviewComments(owner, repo, pullNumber);
      const plan = planInlineComments(findings, {
        commentableLines,
        existingBodies: existing.map((comment) => comment.body),
        maxComments: config.review.maxInlineComments,
        minSeverity: config.review.inlineMinSeverity,
        ...(config.publicUrl ? { dashboardUrl: config.publicUrl } : {}),
        repositoryFullName: `${owner}/${repo}`,
      });

      if (plan.comments.length === 0) {
        logger.debug('no inline comments to post', {
          pullNumber,
          alreadyPosted: plan.alreadyPosted,
          deferred: plan.deferred.length,
        });
        return 0;
      }

      const posted = await this.client.createReviewWithComments(
        owner,
        repo,
        pullNumber,
        headSha,
        plan.comments,
      );
      if (posted === null) return 0;
      logger.info('posted inline comments', {
        pullNumber,
        posted,
        alreadyPosted: plan.alreadyPosted,
        deferred: plan.deferred.length,
      });
      return posted;
    } catch (error) {
      logger.warn('inline comments failed', {
        pullNumber,
        error: (error as Error).message,
      });
      return 0;
    }
  }

  /**
   * Runs the triage pass when it is configured, and gets out of the way when it
   * is not. Refuted findings are dropped only if the operator opted in; by
   * default they stay in the review, labelled, and out of the blocking set.
   */
  private async applyTriage(
    findings: Finding[],
    inputs: FileInput[],
    config: AppConfig,
  ): Promise<{ findings: TriagedFinding[]; summary?: TriageSummary }> {
    const ai = config.ai;
    if (!ai.enabled || findings.length === 0) return { findings };

    const targets = new Map<string, ScanTarget>();
    for (const input of inputs) targets.set(input.filePath, buildTarget(input));

    const pass = await triage(findings, targets, {
      apiKey: ai.apiKey,
      model: ai.model,
      timeoutMs: ai.timeoutMs,
      maxRetries: ai.maxRetries,
      ...(ai.baseUrl ? { baseUrl: ai.baseUrl } : {}),
      ...(ai.fetch ? { fetch: ai.fetch } : {}),
      minSeverity: ai.minSeverity,
      maxFindings: ai.maxFindings,
      contextLines: ai.contextLines,
      maxLinesPerFile: ai.maxLinesPerFile,
      effort: ai.effort,
      maxTokens: ai.maxTokens,
    });

    const kept = ai.dropRefuted
      ? pass.findings.filter((finding) => finding.triage?.verdict !== 'refuted')
      : pass.findings;

    return {
      findings: kept,
      summary: {
        triagedCount: pass.triagedCount,
        refutedCount: pass.refutedCount,
        droppedRefuted: ai.dropRefuted,
        ...(pass.model ? { model: pass.model } : {}),
        ...(pass.error ? { error: pass.error } : {}),
        durationMs: pass.durationMs,
      },
    };
  }

  /**
   * Turns the API's file list into scanner inputs.
   *
   * Rules see the whole post-change file rather than just the added lines, so
   * they can reason about imports and surrounding checks - but `changedLines`
   * restricts what gets *reported*, which is what keeps the reviewer focused on
   * the author's work. When the full file cannot be fetched we fall back to the
   * patch, and accept the narrower context.
   */
  private async buildInputs(
    owner: string,
    repo: string,
    headSha: string,
    files: PullRequestFile[],
    config: AppConfig,
  ): Promise<FileInput[]> {
    const inputs: FileInput[] = [];

    for (const file of files) {
      if (file.status === 'removed' || file.status === 'unchanged') continue;
      const parsed = parsePatch(file.patch);
      // No patch and no additions means a binary or a pure rename.
      if (parsed.changedLines.size === 0 && file.additions === 0) continue;

      let content = await this.client.fileContent(
        owner,
        repo,
        file.filename,
        headSha,
        config.review.maxFileBytes,
      );
      if (content === null) {
        content = reconstructFromPatch(parsed);
        if (content.trim().length === 0) continue;
      }

      inputs.push({
        filePath: file.filename,
        content,
        status: normalizeStatus(file.status),
        // A brand new file is entirely the author's work, so scan all of it.
        changedLines: file.status === 'added' ? null : parsed.changedLines,
      });
    }

    return inputs;
  }

  /**
   * Findings that fail the commit status.
   *
   * A refuted finding never blocks. It stays visible in the comment so a human
   * can disagree, but holding up a merge on a judgement the tool itself
   * believes is wrong would train people to ignore the check.
   */
  private blockingCount(findings: TriagedFinding[], config: AppConfig): number {
    const failOn = config.review.failOnSeverity;
    if (failOn === 'never') return 0;
    return findings.filter(
      (finding) =>
        finding.triage?.verdict !== 'refuted' &&
        SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[failOn as Severity],
    ).length;
  }

  private dashboardUrl(repositoryFullName: string): string | undefined {
    if (!this.config.publicUrl) return undefined;
    return `${this.config.publicUrl}/?repo=${encodeURIComponent(repositoryFullName)}`;
  }
}

/**
 * Lines GitHub will accept a review comment on, per file.
 *
 * Every line the patch shows - added and context alike - is commentable, which
 * is exactly what the diff parser already records positions for. Deletions are
 * not, since they no longer exist on the right-hand side.
 */
/**
 * Applies the repository's per-rule severity replacements.
 *
 * Separate from disabling a rule on purpose: "this rule matters less here" and
 * "this rule is wrong here" are different statements, and collapsing them into
 * one switch means teams silence rules they only wanted to de-prioritise.
 */
function applySeverityOverrides(findings: Finding[], repoConfig: RepoConfig): Finding[] {
  if (repoConfig.severityOverrides.size === 0) return findings;
  return findings.map((finding) => {
    const override =
      repoConfig.severityOverrides.get(finding.ruleId) ??
      repoConfig.severityOverrides.get(finding.category);
    return override ? { ...finding, severity: override } : finding;
  });
}

function collectCommentableLines(files: PullRequestFile[]): Map<string, Set<number>> {
  const out = new Map<string, Set<number>>();
  for (const file of files) {
    if (file.status === 'removed') continue;
    const parsed = parsePatch(file.patch);
    if (parsed.positionByLine.size === 0) continue;
    out.set(file.filename, new Set(parsed.positionByLine.keys()));
  }
  return out;
}

function normalizeStatus(status: PullRequestFile['status']): FileInput['status'] {
  switch (status) {
    case 'added':
      return 'added';
    case 'renamed':
      return 'renamed';
    case 'removed':
      return 'removed';
    default:
      return 'modified';
  }
}
