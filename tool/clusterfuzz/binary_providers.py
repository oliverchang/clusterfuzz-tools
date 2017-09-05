"""Classes to download, build and provide binaries for reproduction."""
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

import base64
import json
import logging
import multiprocessing
import os
import re
import shutil
import stat
import string
import tempfile
import urllib

import urlfetch

from clusterfuzz import common
from clusterfuzz import output_transformer
from error import error


CHECKOUT_MESSAGE = (
    'We want to checkout to the revision {revision}.\n'
    "If you wouldn't like to perform the checkout, "
    'please re-run with --current.\n'
    'Shall we proceed with the following command:\n'
    '{cmd} in {source_dir}?')
ARGS_GN_FILENAME = 'args.gn'
GOMA_DIR = os.path.expanduser(os.path.join('~', 'goma'))

logger = logging.getLogger('clusterfuzz')


def build_revision_to_sha_url(revision, repo):
  return ('https://cr-rev.appspot.com/_ah/api/crrev/v1/get_numbering?%s' %
          urllib.urlencode({
              'number': revision,
              'numbering_identifier': 'refs/heads/master',
              'numbering_type': 'COMMIT_POSITION',
              'project': 'chromium',
              'repo': repo}))


def sha_from_revision(revision, repo):
  """Converts a chrome revision number to it corresponding git sha."""

  response = urlfetch.fetch(build_revision_to_sha_url(revision, repo))
  return json.loads(response.body)['git_sha']


def get_third_party_sha(chromium_sha, key):
  """Gets the correct Pdfium sha using the Chromium sha."""
  response = urlfetch.fetch(
      ('https://chromium.googlesource.com/chromium/src.git/+/%s/DEPS?'
       'format=TEXT' % chromium_sha))
  body = base64.b64decode(response.body)

  sha_line = [l for l in body.split('\n') if "'%s':" % key in l][0]
  sha_line = sha_line.translate(None, string.punctuation).replace(
      key.translate(None, string.punctuation), '')
  return sha_line.strip()


def get_clank_sha(revision_url):
  """Get Clank SHA."""
  tmp_file = tempfile.NamedTemporaryFile(delete=False)
  tmp_file.close()

  common.gsutil('cp %s %s' % (revision_url, tmp_file.name), cwd='.')

  with open(tmp_file.name, 'r') as file_handle:
    body = file_handle.read()
  common.delete_if_exists(tmp_file.name)

  match = re.search('"clank_revision": "([a-fA-F0-9]+)"', body)
  if match:
    return match.group(1)

  raise Exception('Clank SHA is not found in:\n%s' % body)


def sha_exists(sha, source_dir):
  """Check if sha exists."""
  returncode, _ = common.execute(
      'git', 'cat-file -e %s' % sha, cwd=source_dir, exit_on_error=False)
  return returncode == 0


def ensure_sha(sha, source_dir):
  """Ensure the sha exists."""
  if sha_exists(sha, source_dir):
    return

  common.execute('git', 'fetch origin %s' % sha, source_dir)


def is_repo_dirty(path):
  """Returns true if the source dir has uncommitted changes."""
  # `git diff` always return 0 (even when there's change).
  _, diff_result = common.execute(
      'git', 'diff', path, print_command=True, print_output=True)
  return bool(diff_result)


def get_current_sha(source_dir):
  """Return the current sha."""
  _, current_sha = common.execute(
      'git', 'rev-parse HEAD', source_dir, print_command=False,
      print_output=False)
  return current_sha.strip()


def setup_debug_symbol_if_needed(gn_args, sanitizer, enable_debug):
  """Setup debug symbol if enable_debug is true. See: crbug.com/692620"""
  if not enable_debug:
    return gn_args

  gn_args['sanitizer_keep_symbols'] = 'true'
  gn_args['symbol_level'] = '2'

  if sanitizer != 'MSAN':
    gn_args['is_debug'] = 'true'
  return gn_args


def install_build_deps(source_dir, include_lib32):
  """Run install-build-deps.sh."""
  flags = '--syms --no-prompt'
  if include_lib32:
    flags += ' --lib32'

  # preexec_fn is required to be None. Otherwise, it'd fail with:
  # 'sudo: no tty present and no askpass program specified'.
  # See why PATH is added:
  # https://github.com/google/clusterfuzz-tools/issues/497
  common.execute(
      'sudo', 'PATH=$PATH build/install-build-deps.sh %s' % flags, source_dir,
      stdout_transformer=output_transformer.Identity(),
      preexec_fn=None, redirect_stderr_to_stdout=True)


def gclient_runhooks_msan(source_dir, msan_track_origins):
  """Run gclient runhooks for msan."""
  common.execute(
      'gclient', 'runhooks', source_dir,
      env={
          'GYP_DEFINES': (
              'msan=1 msan_track_origins=%s '
              'use_prebuilt_instrumented_libraries=1'
              % (msan_track_origins or '2'))
      }
  )


def ensure_goma():
  """Ensures GOMA is installed and ready for use, and starts it."""
  goma_dir = os.environ.get('GOMA_DIR', GOMA_DIR)
  if not os.path.isfile(os.path.join(goma_dir, 'goma_ctl.py')):
    raise error.GomaNotInstalledError()

  common.execute('python', 'goma_ctl.py ensure_start', goma_dir)
  return goma_dir


def setup_gn_goma_params(gn_args, disable_goma):
  """Ensures that goma_dir and gn_goma are used correctly."""
  if disable_goma:
    gn_args.pop('goma_dir', None)
    gn_args['use_goma'] = 'false'
  else:
    goma_dir = ensure_goma()
    gn_args['use_goma'] = 'true'
    gn_args['goma_dir'] = '"%s"' % goma_dir
  return gn_args


def deserialize_gn_args(args):
  """Deserialize the raw string of gn args into a dict."""
  if not args:
    return {}

  args_hash = {}
  for line in args.splitlines():
    key, val = line.split('=')
    args_hash[key.strip()] = val.strip()
  return args_hash


def serialize_gn_args(args_hash):
  """Serialize the gn args (in the dict form) to raw string."""
  args = []
  for key, val in sorted(args_hash.iteritems()):
    args.append('%s = %s' % (key, val))
  return '\n'.join(args)


def download_build_if_needed(dest, url):
  """Download and extract a build (if it's not already there)."""
  if os.path.exists(dest):
    return dest

  logger.info('Downloading build data...')

  gsutil_path = url.replace(
      'https://storage.cloud.google.com/', 'gs://')
  common.gsutil('cp %s .' % gsutil_path, common.CLUSTERFUZZ_CACHE_DIR)

  filename = os.path.basename(gsutil_path)
  saved_file = os.path.join(common.CLUSTERFUZZ_CACHE_DIR, filename)

  tmp_dir_path = tempfile.mkdtemp(dir=common.CLUSTERFUZZ_TMP_DIR)
  common.execute('unzip', '-q %s -d %s' % (saved_file, tmp_dir_path), cwd='.')

  # args.gn is guaranteed to be in the wanted folder. In Chrome, it's under a
  # sub-directory. In Android, it's in the top dir.
  args_gn_path = common.find_file('args.gn', tmp_dir_path)
  shutil.copytree(os.path.dirname(args_gn_path), dest)

  logger.info('Cleaning up...')
  common.delete_if_exists(saved_file)
  common.delete_if_exists(tmp_dir_path)


def git_checkout(sha, revision, source_dir_path):
  """Checks out the correct revision."""
  if get_current_sha(source_dir_path) == sha:
    logger.info(
        'The current state of %s is already on the revision %s (commit=%s). '
        'No action needed.', source_dir_path, revision, sha)
    return

  binary = 'git'
  args = 'checkout %s' % sha
  common.check_confirm(CHECKOUT_MESSAGE.format(
      revision=revision,
      cmd='%s %s' % (binary, args),
      source_dir=source_dir_path))

  if is_repo_dirty(source_dir_path):
    raise error.DirtyRepoError(source_dir_path)

  ensure_sha(sha, source_dir_path)
  common.execute(binary, args, source_dir_path)


def compute_goma_cores(goma_threads, disable_goma):
  """Choose the correct amount of GOMA cores for a build."""
  if goma_threads:
    return goma_threads

  cpu_count = multiprocessing.cpu_count()

  if disable_goma:
    return (3 * cpu_count) / 4
  else:
    return 50 * cpu_count


def compute_goma_load(goma_load):
  """Choose the correct amount of GOMA load for a build."""
  if goma_load:
    return goma_load
  return multiprocessing.cpu_count() * 2


def get_binary_name(stacktrace):
  """Get the binary name from stacktrace lines."""
  prefix = 'Running command: '
  stacktrace_lines = [l['content'] for l in stacktrace]
  for l in stacktrace_lines:
    if prefix in l:
      l = l.replace(prefix, '').split(' ')
      binary_name = os.path.basename(l[0])
      return binary_name

  raise error.MinimizationNotFinishedError()


def check_gclient_managed(source_name):
  """Check managed=True in .gclient."""
  dot_gclient_path = os.path.realpath(
      os.path.join(source_name, '..', '.gclient'))

  if not os.path.exists(dot_gclient_path):
    return

  with open(dot_gclient_path, 'r') as file_handle:
    content = file_handle.read()

  if re.search('[\'"]managed[\'"]:\\s+True', content):
    raise error.GclientManagedEnabledException(dot_gclient_path)


def get_or_ask_for_source_location(source_name):
  """Returns the location of the source directory."""

  source_env = '%s_SRC' % source_name.upper()

  if os.environ.get(source_env):
    source_directory = os.environ.get(source_env)
  else:
    message = ('This is a %(name)s testcase, please define %(env_name)s'
               ' or enter your %(name)s source location here' %
               {'name': source_name, 'env_name': source_env})

    source_directory = common.get_valid_abs_dir(
        common.ask(
            message, 'Please enter a valid directory',
            common.get_valid_abs_dir))

  check_gclient_managed(source_directory)
  return source_directory


class BinaryProvider(object):
  """Downloads/builds and then provides the location of a binary."""

  def __init__(self, testcase, definition, options):
    self.testcase = testcase
    self.definition = definition
    self.options = options

  @common.memoize
  def get_binary_path(self):
    """Return binary path and ensure it's executable."""
    path = os.path.join(self.get_build_dir_path(), self.get_binary_name())
    stats = os.stat(path)
    os.chmod(path, stats.st_mode | stat.S_IEXEC)
    return path

  def get_build_dir_path(self):
    """Return the build directory."""
    raise NotImplementedError

  @common.memoize
  def get_binary_name(self):
    """Get the binary name."""
    return self.definition.binary_name


class DownloadedBinary(BinaryProvider):
  """Uses a downloaded binary."""

  @common.memoize
  def get_build_dir_path(self):
    """Returns the location of the correct build to use for reproduction."""
    path = os.path.join(
        common.CLUSTERFUZZ_BUILDS_DIR, '%s_downloaded_build' % self.testcase.id)
    download_build_if_needed(path, self.testcase.build_url)
    return path

  # Ensure the downloaded build uses the top dir. Because ClankiumBuilder
  # overrides this method.
  @common.memoize
  def get_binary_path(self):
    """Return the binary path."""
    return BinaryProvider.get_binary_path(self)

  @common.memoize
  def get_source_dir_path(self):
    """Return the chromium source dir path."""
    # Need asan_symbolizer.py from Chromium's source code.
    return get_or_ask_for_source_location('chromium')

  def get_android_libclang_dir_path(self):
    """Get the dir of libclang_rt.asan-*."""
    return self.get_build_dir_path()

  def get_unstripped_lib_dir_path(self):
    """Get the unstripped lib path for Android."""
    return self.get_build_dir_path()

  def build(self):
    """Do nothing."""


class GenericBuilder(BinaryProvider):
  """Provides a base for binary builders."""

  def __init__(
      self, testcase, definition, options):
    """self.git_sha must be set in a subclass, or some of these
    instance methods may not work."""
    super(GenericBuilder, self).__init__(
        testcase=testcase,
        definition=definition,
        options=options)
    # These attributes don't need computation. Therefore, they are not methods.
    self.extra_gn_args = {}
    self.include_lib32 = False

  @common.memoize
  def get_target_names(self):
    """Get the target names."""
    return self.definition.targets

  @common.memoize
  def get_source_dir_path(self):
    """Return the source dir path."""
    return get_or_ask_for_source_location(self.definition.source_name)

  @common.memoize
  def get_main_repo_path(self):
    """Return the main repo path whose SHA is used by `gclient sync` as an
      anchor. Clankium is one example where we build on chromium/src but
      chromium/src/clank is the anchor."""
    return self.get_source_dir_path()

  def get_git_sha(self):
    """Return git sha."""
    raise NotImplementedError

  @common.memoize
  def get_build_dir_path(self):
    """Return the correct out dir in which to build the revision.
      Directory name is of the format clusterfuzz_<testcase_id>_<git_sha>."""
    return os.path.join(
        self.get_source_dir_path(), 'out', 'clusterfuzz_%s' % self.testcase.id)

  @common.memoize
  def get_gn_args(self):
    """Ensures that args.gn is set up properly."""
    args = deserialize_gn_args(self.testcase.raw_gn_args)

    # Add additional options to existing gn args.
    for k, v in self.extra_gn_args.iteritems():
      args[k] = v

    args = setup_gn_goma_params(args, self.options.disable_goma)
    args = setup_debug_symbol_if_needed(
        args, self.definition.sanitizer, self.options.enable_debug)

    return args

  def gn_gen(self):
    """Finalize args.gn and run `gn gen`."""
    args_gn_path = os.path.join(self.get_build_dir_path(), ARGS_GN_FILENAME)

    common.ensure_dir(self.get_build_dir_path())
    common.delete_if_exists(args_gn_path)

    # Let users edit the current args.
    content = serialize_gn_args(self.get_gn_args())
    content = common.edit_if_needed(
        content, prefix='edit-args-gn-',
        comment='Edit %s before building.' % ARGS_GN_FILENAME,
        should_edit=self.options.edit_mode)

    # Write args to file and store.
    with open(args_gn_path, 'w') as f:
      f.write(content)

    logger.info(
        common.colorize('\nGenerating %s:\n%s\n', common.BASH_GREEN_MARKER),
        args_gn_path, content)

    common.execute(
        'gn', 'gen %s' % (self.get_build_dir_path()),
        self.get_source_dir_path())

  def install_deps(self):
    """Run all commands that only need to run once. This means the commands
      within this method are not required to be executed in a subsequential
      run."""
    pass

  def gclient_sync(self):
    """Run gclient sync. This is separated from install_deps because it is
      needed in every build."""
    common.execute(
        'gclient', 'sync', self.get_source_dir_path(),
        # gclient sync sometimes asks a yes/no question (e.g. installing
        # Android SDK).
        stdin=common.StringStdin('y\ny\ny\n'),
    )

  def gclient_runhooks(self):
    """Run gclient runhooks. This is separated from install_deps because it is
      needed in every build, yet the arguments might differ."""
    pass

  def setup_all_deps(self):
    """Setup all dependencies."""
    if self.options.skip_deps:
      return
    self.gclient_sync()
    self.gclient_runhooks()
    self.install_deps()

  def build(self):
    """Build the correct revision in the source directory."""
    if not self.options.current:
      git_checkout(
          self.get_git_sha(), self.testcase.revision,
          self.get_main_repo_path())

    self.setup_all_deps()
    self.gn_gen()

    common.execute(
        'ninja',
        ("-w 'dupbuild=err' -C {build_dir} -j {goma_cores} -l {goma_load} "
         '{targets}'.format(
             build_dir=self.get_build_dir_path(),
             goma_cores=compute_goma_cores(
                 self.options.goma_threads, self.options.disable_goma),
             goma_load=compute_goma_load(self.options.goma_load),
             targets=' '.join(self.get_target_names()))),
        # Unset the memory tools' envs. See:
        # https://github.com/google/clusterfuzz-tools/issues/433
        self.get_source_dir_path(),
        capture_output=False,
        stdout_transformer=output_transformer.Ninja())


class PdfiumBuilder(GenericBuilder):
  """Build a fresh Pdfium binary."""

  def __init__(self, testcase, definition, options):
    super(PdfiumBuilder, self).__init__(
        testcase=testcase,
        definition=definition,
        options=options)
    self.extra_gn_args = {'pdf_is_standalone': 'true'}

  @common.memoize
  def get_git_sha(self):
    """Return git sha."""
    chromium_sha = sha_from_revision(self.testcase.revision, 'chromium/src')
    return get_third_party_sha(chromium_sha, 'pdfium_revision')


class ChromiumBuilder(GenericBuilder):
  """Builds a specific target from inside a Chromium source repository."""

  def __init__(self, testcase, definition, options):
    super(ChromiumBuilder, self).__init__(
        testcase=testcase,
        definition=definition,
        options=options)

  @common.memoize
  def get_git_sha(self):
    """Return git sha."""
    return sha_from_revision(self.testcase.revision, 'chromium/src')

  def install_deps(self):
    """Run all commands that only need to run once. This means the commands
      within this method are not required to be executed in a subsequential
      run."""
    install_build_deps(
        self.get_source_dir_path(), include_lib32=self.include_lib32)
    common.execute('python', 'tools/clang/scripts/update.py',
                   self.get_source_dir_path())

  def gclient_runhooks(self):
    """Run gclient runhooks. This is separated from install_deps because it is
      needed in every build, yet the arguments might differ."""
    common.execute('gclient', 'runhooks', self.get_source_dir_path())


class LibfuzzerAndAflBuilder(ChromiumBuilder):
  """Build a libfuzzer or afl target. The target and binary_name are inferred
    from the stacktrace."""

  @common.memoize
  def get_target_names(self):
    """Get the target name for libfuzzer or afl."""
    return [get_binary_name(self.testcase.stacktrace_lines)]

  @common.memoize
  def get_binary_name(self):
    """Get the binary name."""
    return self.get_target_names()[0]


class V8Builder(GenericBuilder):
  """Builds a fresh v8 binary."""

  def __init__(self, testcase, definition, options):
    super(V8Builder, self).__init__(
        testcase=testcase,
        definition=definition,
        options=options)

  @common.memoize
  def get_git_sha(self):
    """Return git sha."""
    # TODO(tanin): We've migrated all v8 jobs to standalone binaries.
    # All the revisions will be v8's revisions. We can remove this condition
    # and its logic on 6 Dec 2017.
    if self.testcase.revision > 400000:
      chromium_sha = sha_from_revision(self.testcase.revision, 'chromium/src')
      return get_third_party_sha(chromium_sha, 'v8_revision')
    else:
      return sha_from_revision(self.testcase.revision, 'v8/v8')

  def install_deps(self):
    """Run all commands that only need to run once. This means the commands
      within this method are not required to be executed in a subsequential
      run."""
    install_build_deps(
        self.get_source_dir_path(), include_lib32=self.include_lib32)
    common.execute('python', 'tools/clang/scripts/update.py',
                   self.get_source_dir_path())

  def gclient_runhooks(self):
    """Run gclient runhooks. This is separated from install_deps because it is
      needed in every build, yet the arguments might differ."""
    common.execute('gclient', 'runhooks', self.get_source_dir_path())


class CfiMixin(object):
  """Mix CFI settings."""

  def install_deps(self):
    """Run download_gold_plugin.py."""
    super(CfiMixin, self).install_deps()

    if os.path.exists(os.path.join(
        self.get_source_dir_path(), 'build/download_gold_plugin.py')):
      common.execute(
          'build/download_gold_plugin.py', '', self.get_source_dir_path())


class MsanMixin(object):
  """Mix Msan settings."""

  def gclient_runhooks(self):
    """Run gclient runhooks."""
    gclient_runhooks_msan(
        self.get_source_dir_path(),
        self.get_gn_args().get('msan_track_origins'))


class Lib32Mixin(object):
  """Mix lib32 setting."""

  def __init__(self, testcase, definition, options):
    super(Lib32Mixin, self).__init__(
        testcase=testcase,
        definition=definition,
        options=options)
    self.include_lib32 = True


class ChromiumBuilder32Bit(Lib32Mixin, ChromiumBuilder):
  """Build a 32-bit chromium build."""


class V8Builder32Bit(Lib32Mixin, V8Builder):
  """Build a 32-bit V8 build."""


class LibfuzzerMsanBuilder(MsanMixin, LibfuzzerAndAflBuilder):
  """Build libfuzzer_chrome_msan."""


class MsanV8Builder(MsanMixin, V8Builder):
  """Build a MSAN V8 build."""


class MsanChromiumBuilder(MsanMixin, ChromiumBuilder):
  """Build a MSAN Chromium build."""


class CfiV8Builder(CfiMixin, V8Builder):
  """Build a CFI V8 build."""


class CfiChromiumBuilder(CfiMixin, ChromiumBuilder):
  """Build a CFI Chromium build."""


class ClankiumBuilder(ChromiumBuilder):
  """Build Clank."""

  def get_git_sha(self):
    """Return git sha."""
    return get_clank_sha(self.definition.revision_url % self.testcase.revision)

  @common.memoize
  def get_main_repo_path(self):
    """Return the path for Clank. It's the clakium/src/clank."""
    return os.path.join(self.get_source_dir_path(), 'clank')

  def get_binary_path(self):
    """Return the binary path."""
    return '%s/apks/%s' % (self.get_build_dir_path(), self.get_binary_name())

  def install_deps(self):
    """Install deps."""
    super(ClankiumBuilder, self).install_deps()

    # preexec_fn is required to be None. Otherwise, it'd fail with:
    # 'sudo: no tty present and no askpass program specified'.
    # See why PATH is added:
    # https://github.com/google/clusterfuzz-tools/issues/497
    common.execute(
        'sudo', 'PATH=$PATH build/install-build-deps-android.sh',
        self.get_source_dir_path(),
        stdout_transformer=output_transformer.Identity(),
        preexec_fn=None, redirect_stderr_to_stdout=True)

  def get_android_libclang_dir_path(self):
    """Get the dir of libclang_rt.asan-*."""
    parent_dir = os.path.join(
        self.get_source_dir_path(), 'third_party', 'llvm-build',
        'Release+Asserts', 'lib', 'clang')
    version = os.listdir(parent_dir)[0]
    return os.path.join(parent_dir, version, 'lib', 'linux')

  def get_unstripped_lib_dir_path(self):
    """Get the unstripped lib path for Android."""
    return os.path.join(self.get_build_dir_path(), 'lib.unstripped')
