"""Module for the Testcase class."""
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import zipfile
import logging

from clusterfuzz import common


CLUSTERFUZZ_TESTCASE_URL = (
    'https://%s/v2/testcase-detail/download-testcase?id=%s' %
    (common.DOMAIN_NAME, '%s'))
DOWNLOAD_TIMEOUT = 100
logger = logging.getLogger('clusterfuzz')


def get_file_extension(absolute_path):
  """Pulls the file extension from the path, returns '' if no extension."""
  split_filename = absolute_path.split('.')
  if len(split_filename) < 2:
    return ''
  else:
    return '.%s' % split_filename[-1]


def _unescape(string):
  """Un-escape a string."""
  string = string.replace("&lt;", "<")
  string = string.replace("&gt;", ">")
  string = string.replace("&apos;", "'")
  string = string.replace("&quot;", "\"")
  # This has to be last call.
  string = string.replace("&amp;", "&")
  return string


def get_environment_and_args(stacktrace_lines):
  """Sets up the environment by parsing stacktrace lines."""

  new_env = {}
  args = ''
  stacktrace_lines = [
      _unescape(line['content']) for line in stacktrace_lines]
  for line in stacktrace_lines:
    if '[Environment] ' in line:
      line = line.replace('[Environment] ', '')
      tokens = line.split(' = ', 1)
      if len(tokens) != 2:
        continue
      name, value = tokens

      if '_OPTIONS' in name:
        value = value.replace('symbolize=0', 'symbolize=1')
        if 'symbolize=1' not in value:
          value += ':symbolize=1'
      new_env[name] = value

    elif 'Running command: ' in line:
      line = line.replace('Running command: ', '').split(' ')

      # Strip off the binary & testcase paths.
      line = line[1:len(line)-1]

      args = " ".join(line)

  return new_env, args


def create(testcase_json):
  """Parse testcase json and instantiate a Testcase."""
  stacktrace_lines = testcase_json['crash_stacktrace']['lines']
  environment, reproduction_args = get_environment_and_args(stacktrace_lines)
  if not reproduction_args:
    reproduction_args = (
        '%s %s' % (testcase_json['testcase']['window_argument'],
                   testcase_json['testcase']['minimized_arguments'])).strip()
  absolute_path = testcase_json['testcase']['absolute_path']

  return Testcase(
      testcase_id=testcase_json['id'],
      stacktrace_lines=stacktrace_lines,
      environment=environment,
      reproduction_args=reproduction_args,
      revision=testcase_json['crash_revision'],
      build_url=testcase_json['metadata']['build_url'],
      job_type=testcase_json['testcase']['job_type'],
      absolute_path=absolute_path,
      file_extension=get_file_extension(absolute_path),
      reproducible=not testcase_json['testcase']['one_time_crasher_flag'],
      gestures=testcase_json['testcase'].get('gestures'),
      crash_type=testcase_json['crash_type'],
      crash_state=testcase_json['crash_state'],
      raw_gn_args=testcase_json['metadata'].get('gn_args', '').strip())


class Testcase(object):
  """The Testase module, to abstract away logic using the testcase JSON."""

  def __init__(
      self, testcase_id, stacktrace_lines, environment, reproduction_args,
      revision, build_url, job_type, absolute_path, file_extension,
      reproducible, gestures, crash_type, crash_state, raw_gn_args):
    self.id = testcase_id
    self.stacktrace_lines = stacktrace_lines
    self.environment = environment
    self.reproduction_args = reproduction_args
    self.revision = revision
    self.build_url = build_url
    self.job_type = job_type
    self.absolute_path = absolute_path
    self.file_extension = file_extension
    self.reproducible = reproducible
    self.gestures = gestures
    self.crash_type = crash_type
    self.crash_state = crash_state
    self.raw_gn_args = raw_gn_args

    self.testcase_dir_path = os.path.join(
        common.CLUSTERFUZZ_TESTCASES_DIR, str(self.id) + '_testcase')

  @common.memoize
  def get_true_testcase_path(self, filename):
    """Return actual testcase path, unzips testcase if required."""
    if filename.endswith('.zip'):
      zipped_file = zipfile.ZipFile(os.path.join(
          self.testcase_dir_path, filename), 'r')
      zipped_file.extractall(self.testcase_dir_path)
      zipped_file.close()
      return os.path.join(self.testcase_dir_path, self.absolute_path)
    else:
      true_testcase_path = os.path.join(
          self.testcase_dir_path, 'testcase%s' % self.file_extension)
      current_testcase_path = os.path.join(self.testcase_dir_path, filename)
      os.rename(current_testcase_path, true_testcase_path)
      return true_testcase_path

  @common.memoize
  def get_testcase_path(self):
    """Downloads & returns the location of the testcase file."""
    common.delete_if_exists(self.testcase_dir_path)
    os.makedirs(self.testcase_dir_path)

    logger.info('Downloading testcase data...')

    auth_header = common.get_stored_auth_header()
    # Do not use curl because curl doesn't support downloading an empty file.
    # See: https://github.com/google/clusterfuzz-tools/issues/326
    args = (
        '--no-verbose --waitretry=%s --retry-connrefused --content-disposition '
        '--header="Authorization: %s" "%s"' %
        (DOWNLOAD_TIMEOUT, auth_header, CLUSTERFUZZ_TESTCASE_URL % self.id))
    common.execute('wget', args, self.testcase_dir_path)
    downloaded_filename = os.listdir(self.testcase_dir_path)[0]

    return self.get_true_testcase_path(downloaded_filename)
