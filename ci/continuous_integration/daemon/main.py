"""The main module for the CI server."""

import collections
import os
import shutil
import sys
import time
import yaml

import requests
from requests.packages.urllib3.util import retry
from requests import adapters
from oauth2client.client import GoogleCredentials

from daemon import stackdriver_logging
from daemon import process
from error import error


HOME = os.path.expanduser('~')
CLUSTERFUZZ_DIR = os.path.join(HOME, '.clusterfuzz')
CLUSTERFUZZ_LOG_PATH = os.path.join(CLUSTERFUZZ_DIR, 'logs', 'output.log')
CLUSTERFUZZ_CACHE_DIR = os.path.join(CLUSTERFUZZ_DIR, 'cache')
AUTH_FILE_LOCATION = os.path.join(CLUSTERFUZZ_CACHE_DIR, 'auth_header')
CHROMIUM_SRC = os.path.join(HOME, 'chromium', 'src')
CHROMIUM_OUT = os.path.join(CHROMIUM_SRC, 'out')
RELEASE_ENV = os.path.join(HOME, 'RELEASE_ENV')
DEPOT_TOOLS = os.path.join(HOME, 'depot_tools')
SANITY_CHECKS = '/python-daemon/daemon/sanity_checks.yml'
BINARY_LOCATION = '/python-daemon-data/clusterfuzz'
TOOL_SOURCE = os.path.join(HOME, 'clusterfuzz-tools')
MAX_PREVIEW_LOG_BYTE_COUNT = 100000

PROCESSED_TESTCASE_IDS = set()
RETRIABLE_RETURN_CODES = set([
    error.MinimizationNotFinishedError.EXIT_CODE
])

# The options that will be tested on the CI.
TEST_OPTIONS = ['', '--current --skip-deps']

# The number of seconds to sleep after each test run to avoid DDOS.
SLEEP_TIME = 30

Testcase = collections.namedtuple('Testcase', ['id', 'job_type'])


# Configuring backoff retrying because sending a request to ClusterFuzz
# might fail during a deployment.
http = requests.Session()
http.mount(
    'https://',
    adapters.HTTPAdapter(
        # backoff_factor is 0.5. Therefore, the max wait time is 16s.
        retry.Retry(
            total=5, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504]))
)


def post(*args, **kwargs):  # pragma: no cover
  """Make a post request. This method is needed for mocking."""
  return http.post(*args, **kwargs)


def load_sanity_check_testcase_ids():
  """Return a list of all testcases to try."""
  with open(SANITY_CHECKS) as stream:
    return yaml.load(stream)['testcase_ids']


def build_command(args):
  """Returns the command to run the binary."""
  return '%s %s' % (BINARY_LOCATION, args)


def run_testcase(testcase_id, opts):
  """Attempts to reproduce a testcase."""
  return_code, _ = process.call(
      ('%s reproduce %s %s' % (BINARY_LOCATION, testcase_id, opts)).strip(),
      cwd=HOME,
      env={
          'CF_QUIET': '1',
          'USER': 'CI',
          'CHROMIUM_SRC': CHROMIUM_SRC,
          'GOMA_GCE_SERVICE_ACCOUNT': 'default',
          'PATH': '%s:%s' % (os.environ['PATH'], DEPOT_TOOLS)
      },
      raise_on_error=False
  )

  # If the return code is retriable, we don't store it in
  # PROCESSED_TESTCASE_IDS. This means the testcase will be run again in the
  # next batch.
  if return_code not in RETRIABLE_RETURN_CODES:
    PROCESSED_TESTCASE_IDS.add(testcase_id)

  return return_code


def update_auth_header():
  """Sets the correct auth token in the clusterfuzz dir."""

  service_credentials = GoogleCredentials.get_application_default()
  if not os.path.exists(CLUSTERFUZZ_CACHE_DIR):
    os.makedirs(CLUSTERFUZZ_CACHE_DIR)
  new_auth_token = service_credentials.get_access_token()

  with open(AUTH_FILE_LOCATION, 'w') as f:
    f.write('Bearer %s' % new_auth_token.access_token)
  os.chmod(AUTH_FILE_LOCATION, 0600)


def get_binary_version():
  """Returns the version of the binary."""
  _, out = process.call(build_command('supported_job_types'), capture=True)
  return yaml.load(out)['Version']


def get_supported_jobtypes():
  """Returns a hash of supported job types."""
  _, out = process.call(build_command('supported_job_types'), capture=True)
  result = yaml.load(out)
  result.pop('Version', None)
  return result


def load_new_testcases():
  """Returns a new list of testcases from clusterfuzz to run."""

  with open(AUTH_FILE_LOCATION, 'r') as f:
    auth_header = f.read()

  testcases = []
  added_testcase_ids = set()
  page = 1
  supported_jobtypes = get_supported_jobtypes()

  while len(testcases) < 20 and page < 30:
    r = post('https://clusterfuzz.com/v2/testcases/load',
             headers={'Authorization': auth_header},
             json={'page': page, 'reproducible': 'yes',
                   'q': 'platform:linux', 'open': 'yes'})
    page += 1

    items = r.json()['items']
    if not items:
      break

    for testcase in items:
      if testcase['jobType'] not in supported_jobtypes['chromium']:
        print 'Skip %s (%s) because its job type is not supported.' % (
            testcase['id'], testcase['jobType'])
        continue

      if (testcase['id'] in PROCESSED_TESTCASE_IDS or
          testcase['id'] in added_testcase_ids):
        continue

      testcases.append(Testcase(testcase['id'], testcase['jobType']))
      added_testcase_ids.add(testcase['id'])

  return testcases


def delete_if_exists(path):
  """Delete filename if the file exists."""
  if os.path.isdir(path):
    shutil.rmtree(path, True)
  elif os.path.exists(path):
    os.remove(path)


def build_master_and_get_version():
  """Checks out the latest master build and creates a new binary."""
  if not os.path.exists(TOOL_SOURCE):
    process.call(
        'git clone https://github.com/google/clusterfuzz-tools.git', cwd=HOME)
  process.call('git fetch', cwd=TOOL_SOURCE)
  process.call('git checkout origin/master -f', cwd=TOOL_SOURCE)
  process.call('./pants binary tool:clusterfuzz-ci', cwd=TOOL_SOURCE,
               env={'HOME': HOME})

  delete_if_exists(BINARY_LOCATION)
  shutil.copy(os.path.join(TOOL_SOURCE, 'dist', 'clusterfuzz-ci.pex'),
              BINARY_LOCATION)

  # The full SHA is too long and unpleasant to show in logs. So, we use the
  # first 7 characters of the SHA instead.
  return process.call(
      'git rev-parse HEAD', capture=True, cwd=TOOL_SOURCE)[1].strip()[:7]


def prepare_binary_and_get_version(release):
  """Get version given the release name."""
  if release == 'master':
    return build_master_and_get_version()
  else:
    return get_binary_version()


def read_logs(path=CLUSTERFUZZ_LOG_PATH):
  """Read the logs."""
  if not os.path.exists(path):
    return "%s doesn't exist." % path

  preview_byte_count = min(MAX_PREVIEW_LOG_BYTE_COUNT, os.path.getsize(path))

  with open(path, 'r') as f:
    # Jump to the 100,000 bytes from the end.
    f.seek(-preview_byte_count, 2)
    return '--- The last %d bytes of the log file ---\n%s' % (
        preview_byte_count, f.read())


def reset_and_run_testcase(testcase_id, category, release):
  """Resets the chromium repo and runs the testcase."""

  delete_if_exists(CHROMIUM_OUT)
  delete_if_exists(CLUSTERFUZZ_CACHE_DIR)
  process.call('git checkout -f HEAD', cwd=CHROMIUM_SRC)

  # Clean untracked files. Because untracked files in submodules are not removed
  # with `git checkout -f HEAD`. `git clean -ffddx` also cleans untracked
  # sub-repositories and ignored files. Anecdotally, ignored files cause
  # failure in `gclient sync` and `gn gen`. The caveat is that `gclient sync`
  # takes longer.
  process.call('git clean -ffddx', cwd=CHROMIUM_SRC)

  version = prepare_binary_and_get_version(release)

  for opts in TEST_OPTIONS:
    update_auth_header()
    return_code = run_testcase(testcase_id, opts=opts)
    logs = read_logs()

    stackdriver_logging.send_run(
        testcase_id, category, version, release, return_code, logs, opts)


def main():
  release = sys.argv[1]

  for testcase_id in load_sanity_check_testcase_ids():
    reset_and_run_testcase(testcase_id, 'sanity', release)
    time.sleep(SLEEP_TIME)

  while True:
    update_auth_header()
    for testcase in load_new_testcases():
      reset_and_run_testcase(testcase.id, testcase.job_type, release)
      time.sleep(SLEEP_TIME)
