import { parsePatch, reconstructFromPatch } from '../analysis/diff';
import { scan, type FileInput } from '../analysis/engine';
import { SEVERITY_RANK, type Finding, type Severity } from '../analysis/types';
import type { AppConfig } from '../config';
import type { ReviewStore } from '../storage/database';
import { logger } from '../util/logger';
import { COMMENT_MARKER, renderComment, renderStatusDescription } from './comment';
import type { GitHubClient, PullRequestFile } from './client';

/**
 * End-to-end review of one pull request.
 *
 * The sequence is deliberately linear and idempotent: a re-run on the same head
 * SHA produces the same comment and the same status, which matters because
 * GitHub redelivers webhooks and because authors push repeatedly.
 */

export interface ReviewRequest {
  owner: string;
  repo: string;
  pullNumber: number;
}

export interface ReviewOutcome {
  scanId: number;
  findings: Finding[];
  filesScanned: number;
  newFindings: number;
  resolvedFindings: number;
  status: 'success' | 'failure';
  skipped?: string;
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

    if (pullRequest.changedFiles > this.config.review.maxFilesPerPullRequest) {
      const reason =
        `pull request touches ${pullRequest.changedFiles} files, above the ` +
        `${this.config.review.maxFilesPerPullRequest}-file limit`;
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
    const inputs = await this.buildInputs(owner, repo, pullRequest.headSha, files);

    const summary = scan(inputs, {
      minSeverity: this.config.review.minSeverity,
      maxFindingsPerFile: this.config.review.maxFindingsPerFile,
      includeTests: this.config.review.includeTests,
      disabledRules: this.config.review.disabledRules,
    });

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
      findings: summary.findings,
      examined: inputs.map((input) => ({
        path: input.filePath,
        lines: input.changedLines === null ? null : [...input.changedLines],
      })),
    });

    const newFingerprints = new Set(
      summary.findings
        .filter((finding) => !previouslyOpen.has(finding.fingerprint))
        .map((finding) => finding.fingerprint),
    );

    const body = renderComment(summary.findings, {
      repositoryFullName,
      headSha: pullRequest.headSha,
      filesScanned: summary.filesScanned,
      durationMs: summary.durationMs,
      newFingerprints,
      resolvedCount: record.resolvedFingerprints.length,
      maxRendered: this.config.review.maxFindingsPerComment,
      dashboardUrl: this.config.publicUrl,
      failOnSeverity: this.config.review.failOnSeverity,
    });

    const comment = await this.client.upsertComment(owner, repo, pullNumber, COMMENT_MARKER, body);

    const blocking = this.blockingCount(summary.findings);
    const status: 'success' | 'failure' = blocking > 0 ? 'failure' : 'success';
    await this.client.setCommitStatus(
      owner,
      repo,
      pullRequest.headSha,
      status,
      renderStatusDescription(summary.findings, this.config.review.failOnSeverity),
      this.dashboardUrl(repositoryFullName),
    );

    logger.info('review complete', {
      repository: repositoryFullName,
      pullNumber,
      findings: summary.findings.length,
      newFindings: newFingerprints.size,
      resolved: record.resolvedFingerprints.length,
      blocking,
      commentUpdated: comment.updated,
      totalMs: Date.now() - started,
    });

    return {
      scanId: record.scanId,
      findings: summary.findings,
      filesScanned: summary.filesScanned,
      newFindings: newFingerprints.size,
      resolvedFindings: record.resolvedFingerprints.length,
      status,
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
        this.config.review.maxFileBytes,
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

  private blockingCount(findings: Finding[]): number {
    const failOn = this.config.review.failOnSeverity;
    if (failOn === 'never') return 0;
    return findings.filter((finding) => SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[failOn as Severity])
      .length;
  }

  private dashboardUrl(repositoryFullName: string): string | undefined {
    if (!this.config.publicUrl) return undefined;
    return `${this.config.publicUrl}/?repo=${encodeURIComponent(repositoryFullName)}`;
  }
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
