
import sys
import time
import os
import json
from datetime import datetime, timedelta, timezone
import logging
from typing import Optional

import git
from git import Repo


keyword_list = ['jira', 'confluence', 'bigbluebutton']
repo_url = 'https://github.com/CVEProject/cvelist.git'
repo_path = 'cvelist'
interval = timedelta(days=30)


class CVEChecker:
    def __init__(self):
        self.repo: Optional[Repo] = None

    def fetch_repo(self):
        if not os.path.isdir(repo_path):
            Repo.clone_from(repo_url, repo_path)
        else:
            repo = Repo(repo_path)
            for remote in repo.remotes:
                remote.fetch()

    def get_last_commit_from(self, date_time: datetime) -> Optional[git.Commit]:
        last_commit = None
        for commit in self.repo.iter_commits('master', max_count=100000):
            if commit.committed_datetime < date_time:
                break
            last_commit = commit
        else:
            logging.warning(f'No commit older than {interval} found. Using oldest commit.')
        return last_commit

    def get_new_cves(self, start_commit: git.Commit):
        new = set()
        diff = start_commit.diff(self.repo.head.commit)
        for diff_obj in diff:
            # A -> Added; M -> Modified data;
            if diff_obj.change_type == 'A':
                new.add(os.path.join(repo_path, diff_obj.b_path))
            elif diff_obj.change_type == 'M':
                old_state = json.loads(diff_obj.a_blob.data_stream.read().decode())['CVE_data_meta']['STATE']
                new_state = json.loads(diff_obj.b_blob.data_stream.read().decode())['CVE_data_meta']['STATE']
                if not old_state == 'PUBLIC' \
                   and new_state == 'PUBLIC':
                    new.add(os.path.join(repo_path, diff_obj.a_path))
        return new

    def search_cves_for_keywords(self, cve_paths):
        matches = []
        for path in cve_paths:
            file = open(path)
            s = file.read()
            file.close()
            cve = json.loads(s)
            state = cve['CVE_data_meta']['STATE']
            if state == 'PUBLIC':
                # don't search the whole file, they often include jira ticket links and similar
                affects = json.dumps(cve['affects']).lower()
                for keyword in keyword_list:
                    if keyword in affects:
                        matches.append(cve)
        return matches

    def run(self):
        print(f'Looking for: {keyword_list}')
        print(f'within last {interval}')
        print()
        #self.fetch_repo()
        self.repo = Repo(repo_path)
        offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        local_timezone = timezone(timedelta(seconds=offset))
        utc_timezone = timezone(timedelta())
        now = datetime.now(local_timezone)
        start_date = now - interval
        start_commit = self.get_last_commit_from(start_date)
        if not start_commit:
            logging.info(f'No commit within last {interval}')
            sys.exit(0)
        print('Diff commit:', start_commit, time.asctime(time.gmtime(start_commit.committed_date)))
        paths = self.get_new_cves(start_commit)
        matches = self.search_cves_for_keywords(paths)
        for cve in matches:
            meta = cve['CVE_data_meta']
            date_public = datetime.fromisoformat(meta['DATE_PUBLIC']).astimezone(utc_timezone)
            date_public_delta = (now - date_public)
            if date_public_delta.days:
                dt = str(date_public_delta.days)
            else:
                dt = str(timedelta(seconds=date_public_delta.seconds))
            print(f'{meta["ID"]} - {dt} ago - {cve["affects"]}')


if __name__ == '__main__':
    CVEChecker().run()
