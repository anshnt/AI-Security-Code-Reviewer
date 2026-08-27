import { Octokit } from '@octokit/rest';
import { logger } from '../util/logger';

/**
 * Thin wrapper over the REST client.
 *
 * Everything the reviewer needs from GitHub goes through here, which keeps the
 * retry policy, the size guards and the "comment already exists" logic in one
 * place instead of scattered through the orchestration code.
 */

export interface PullRequestFile {
  filename: string;
  previousFilename?: string;
  status: 'added' | 'modified' | 'removed' | 'renamed' | 'copied' | 'changed' | 'unchanged';
  additions: number;
  deletions: number;
  patch?: string;
  sha: string;
}

export interface ReviewComment {
  path: string;
  /** Line in the post-change file. */
  line: number;
  body: string;
}

export interface ExistingReviewComment {
  id: number;
  path: string;
  body: string;
}

export interface PullRequestInfo {
  number: number;
  title: string;
  headSha: string;
  baseSha: string;
  author: string;
  draft: boolean;
  changedFiles: number;
}

export class GitHubClient {
  private readonly octokit: Octokit;

  constructor(token: string, baseUrl = 'https://api.github.com') {
    this.octokit = new Octokit({
      auth: token,
      baseUrl,
      userAgent: 'ai-security-code-reviewer',
      request: { timeout: 20_000 },
    });
  }

  async pullRequest(owner: string, repo: string, pullNumber: number): Promise<PullRequestInfo> {
    const { data } = await this.octokit.pulls.get({ owner, repo, pull_number: pullNumber });
    return {
      number: data.number,
      title: data.title,
      headSha: data.head.sha,
      baseSha: data.base.sha,
      author: data.user?.login ?? 'unknown',
      draft: Boolean(data.draft),
      changedFiles: data.changed_files,
    };
  }

  /** All changed files, paginated. */
  async pullRequestFiles(owner: string, repo: string, pullNumber: number): Promise<PullRequestFile[]> {
    const files = await this.octokit.paginate(this.octokit.pulls.listFiles, {
      owner,
      repo,
      pull_number: pullNumber,
      per_page: 100,
    });
    return files.map((file) => ({
      filename: file.filename,
      ...(file.previous_filename ? { previousFilename: file.previous_filename } : {}),
      status: file.status,
      additions: file.additions,
      deletions: file.deletions,
      ...(file.patch ? { patch: file.patch } : {}),
      sha: file.sha,
    }));
  }

  /**
   * Full text of a file at a given ref. Returns `null` for binaries, files too
   * large for the contents API, and anything that has been deleted - callers
   * fall back to the patch in those cases.
   */
  async fileContent(
    owner: string,
    repo: string,
    path: string,
    ref: string,
    maxBytes: number,
  ): Promise<string | null> {
    try {
      const { data } = await this.octokit.repos.getContent({ owner, repo, path, ref });
      if (Array.isArray(data) || data.type !== 'file') return null;
      if (data.size > maxBytes) {
        logger.debug('skipping oversized file', { path, size: data.size });
        return null;
      }
      if (data.content) {
        const decoded = Buffer.from(data.content, 'base64');
        if (isProbablyBinary(decoded)) return null;
        return decoded.toString('utf8');
      }
      // Files above 1MB come back without inline content; fetch the blob.
      const blob = await this.octokit.git.getBlob({ owner, repo, file_sha: data.sha });
      const decoded = Buffer.from(blob.data.content, 'base64');
      if (isProbablyBinary(decoded)) return null;
      return decoded.toString('utf8');
    } catch (error) {
      const status = (error as { status?: number }).status;
      if (status === 404 || status === 403) return null;
      throw error;
    }
  }

  /**
   * Posts the review summary, replacing the previous one from this tool so a PR
   * accumulates one comment rather than one per push.
   */
  async upsertComment(
    owner: string,
    repo: string,
    issueNumber: number,
    marker: string,
    body: string,
  ): Promise<{ id: number; updated: boolean }> {
    const existing = await this.octokit.paginate(this.octokit.issues.listComments, {
      owner,
      repo,
      issue_number: issueNumber,
      per_page: 100,
    });
    const mine = existing.find((comment) => comment.body?.includes(marker));

    if (mine) {
      const { data } = await this.octokit.issues.updateComment({
        owner,
        repo,
        comment_id: mine.id,
        body,
      });
      return { id: data.id, updated: true };
    }
    const { data } = await this.octokit.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body,
    });
    return { id: data.id, updated: false };
  }

  /**
   * Review comments already on this pull request, so a re-push does not repeat
   * itself. GitHub keeps review comments forever - it only marks them outdated
   * when the line moves - so the reviewer has to deduplicate rather than relying
   * on the platform.
   */
  async listReviewComments(
    owner: string,
    repo: string,
    pullNumber: number,
  ): Promise<ExistingReviewComment[]> {
    const comments = await this.octokit.paginate(this.octokit.pulls.listReviewComments, {
      owner,
      repo,
      pull_number: pullNumber,
      per_page: 100,
    });
    return comments.map((comment) => ({
      id: comment.id,
      path: comment.path,
      body: comment.body ?? '',
    }));
  }

  /**
   * Posts inline comments as a single review.
   *
   * One review rather than N standalone comments, for two reasons: it is one
   * notification instead of N, and GitHub rejects the whole review if any
   * comment is unanchorable, which surfaces the problem instead of silently
   * dropping findings.
   *
   * Returns the number of comments posted, or `null` when GitHub refused the
   * review - which happens when a line is not part of the diff GitHub is
   * willing to show, typically because the file is too large. Callers fall back
   * to the summary comment rather than losing the findings.
   */
  async createReviewWithComments(
    owner: string,
    repo: string,
    pullNumber: number,
    commitId: string,
    comments: ReviewComment[],
  ): Promise<number | null> {
    if (comments.length === 0) return 0;
    try {
      await this.octokit.pulls.createReview({
        owner,
        repo,
        pull_number: pullNumber,
        commit_id: commitId,
        // COMMENT, never REQUEST_CHANGES: blocking a merge is the commit
        // status's job, and a changes-requested review from a bot has to be
        // dismissed by a human before anything can merge.
        event: 'COMMENT',
        comments: comments.map((comment) => ({
          path: comment.path,
          line: comment.line,
          side: 'RIGHT',
          body: comment.body,
        })),
      });
      return comments.length;
    } catch (error) {
      const status = (error as { status?: number }).status;
      // 422 means at least one line was not commentable.
      if (status === 422) {
        logger.warn('inline review rejected', {
          pullNumber,
          comments: comments.length,
          reason: (error as Error).message,
        });
        return null;
      }
      throw error;
    }
  }

  /** Reports the review outcome as a commit status so it can gate merges. */
  async setCommitStatus(
    owner: string,
    repo: string,
    sha: string,
    state: 'success' | 'failure' | 'pending' | 'error',
    description: string,
    targetUrl?: string,
  ): Promise<void> {
    await this.octokit.repos.createCommitStatus({
      owner,
      repo,
      sha,
      state,
      context: 'security-review',
      description: description.slice(0, 140),
      ...(targetUrl ? { target_url: targetUrl } : {}),
    });
  }
}

/** A NUL byte in the first kilobyte is the standard binary heuristic. */
function isProbablyBinary(buffer: Buffer): boolean {
  const window = buffer.subarray(0, 1024);
  return window.includes(0);
}
