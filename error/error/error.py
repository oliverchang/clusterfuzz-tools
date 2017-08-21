"""Expected errors."""

import inspect
import sys


UNREPRODUCIBLE_SUGGESTION_TEXT = (
    'Here are things you can try:\n'
    '- Run outside XVFB (e.g. you will be able to see the launched program '
    'on screen.) with `--disable-xvfb`, which is especially useful for '
    'Chrome.\n'
    '- Run with the downloaded build by adding `--build download`.\n'
    '- Run `build/install-build-deps.sh` to ensure all dependencies are '
    'installed.\n'
    '- Run with more number of trials by adding `-i 10`, '
    'which is especially good for gesture-related testcases.\n'
    '- Use gdb to debug by adding `--enable-debug`.')



def get_class(exit_code):
  """Get class name given an exit code."""
  code_to_klass = {}
  for _, obj in inspect.getmembers(sys.modules[__name__]):
    if inspect.isclass(obj) and obj != ExpectedException:
      if obj.EXIT_CODE not in code_to_klass:
        code_to_klass[obj.EXIT_CODE] = obj
      else:
        raise Exception(
            '%s and %s have the same exit code.' % (
                code_to_klass[obj.EXIT_CODE].__name__, obj.__name__))
  return code_to_klass.get(exit_code, UnknownExitCodeError)


class ExpectedException(Exception):
  """A general Exception to extend from."""

  def __init__(self, message, exit_code, extras=None):
    super(ExpectedException, self).__init__(message)
    self.extras = extras
    self.exit_code = exit_code


class UnknownExitCodeError(ExpectedException):
  """Represents an unknown exit code error."""

  EXIT_CODE = 256


class MinimizationNotFinishedError(ExpectedException):
  """Raise when the minimize_task failed or hasn't finished yet. When the
    minimization is not finished, we won't find 'Running command: ' in the
    stacktrace."""

  MESSAGE = (
      "The testcase hasn't been minimized yet or cannot be minimized.\n"
      'If the testcase is new, please wait for a few more hours.\n'
      "If we can't minimize the testcase, it means the testcase is "
      'unreproducible and, thus, not supported by this tool.')
  EXIT_CODE = 42

  def __init__(self):
    super(MinimizationNotFinishedError, self).__init__(
        self.MESSAGE, self.EXIT_CODE)


class SanitizerNotProvidedError(ExpectedException):
  """An error to notify when a sanitizer isn't passed to a Definition"""

  MESSAGE = 'A sanitizer must be provided with each Definition.'
  EXIT_CODE = 43

  def __init__(self):
    super(SanitizerNotProvidedError, self).__init__(
        self.MESSAGE, self.EXIT_CODE)


class ClusterFuzzError(ExpectedException):
  """An exception to deal with clusterfuzz.com's errors.

  Makes the response dict available for inspection later on when
  the exception is dealt with."""

  MESSAGE = (
      "Error calling clusterfuzz.com's API. \nHere's the response: {response}")
  EXIT_CODE = 44

  def __init__(self, status_code, response):
    super(ClusterFuzzError, self).__init__(
        self.MESSAGE.format(response=str(response)), self.EXIT_CODE)
    self.status_code = status_code
    self.response = response


class PermissionsTooPermissiveError(ExpectedException):
  """An exception to deal with file permissions errors.

  Stores the filename and the current permissions.."""

  MESSAGE = ('File permissions too permissive to open {filename}\n'
             'Current permissions: {permission}\nExpected user access only'
             '\nYou can run "chmod 600 {filename}filename" to fix this issue')
  EXIT_CODE = 45

  def __init__(self, filename, current_permissions):
    super(PermissionsTooPermissiveError, self).__init__(
        self.MESSAGE.format(filename=filename, permission=current_permissions),
        self.EXIT_CODE)
    self.filename = filename
    self.current_permissions = current_permissions


class GomaNotInstalledError(ExpectedException):
  """An exception to tell people GOMA isn not installed."""

  MESSAGE = ('Either goma is not installed, or $GOMA_DIR is not set.'
             ' Please set up goma before continuing. '
             'See go/ma to learn more.\n\n'
             "If you wouldn't like to use goma, "
             'please re-run with --disable-goma.')
  EXIT_CODE = 46

  def __init__(self):
    super(GomaNotInstalledError, self).__init__(self.MESSAGE, self.EXIT_CODE)


class JobTypeNotSupportedError(ExpectedException):
  """An exception raised when user tries to run an unsupported build type."""

  MESSAGE = (
      'Unfortunately, the job {job_type} is not yet supported.'
      'If you believe that the crash will occur on Linux as well, please go '
      'to https://clusterfuzz.com/uploadusertestcase, upload the testcase, '
      'and choose a corresponding Linux job type. Ask us for help at '
      'clusterfuzz-dev@chromium.org.')
  EXIT_CODE = 47

  def __init__(self, job_type):
    super(JobTypeNotSupportedError, self).__init__(
        self.MESSAGE.format(job_type=job_type), self.EXIT_CODE)


class NotInstalledError(ExpectedException):
  """An exception raised to tell the user to install the required binary."""

  MESSAGE = (
      '{binary} is not found. Please install it or ensure the path is '
      'correct.\n'
      'Most of the time you can install it with `apt-get install {binary}`.')
  EXIT_CODE = 48

  def __init__(self, binary):
    super(NotInstalledError, self).__init__(
        self.MESSAGE.format(binary=binary), self.EXIT_CODE)


class GsutilNotInstalledError(ExpectedException):
  """An exception raised to tell the user to install the required binary."""

  MESSAGE = (
      'gsutil is not installed. Please install it. See:'
      'https://cloud.google.com/storage/docs/gsutil_install')
  EXIT_CODE = 49

  def __init__(self):
    super(GsutilNotInstalledError, self).__init__(self.MESSAGE, self.EXIT_CODE)


class BadJobTypeDefinitionError(ExpectedException):
  """An exception raised when a job type description is malformed."""

  MESSAGE = (
      'The definition for the {job_type} job type is incorrectly formatted or'
      ' missing crucial information.')
  EXIT_CODE = 50

  def __init__(self, job_type):
    super(BadJobTypeDefinitionError, self).__init__(
        self.MESSAGE.format(job_type=job_type), self.EXIT_CODE)


class UnreproducibleError(ExpectedException):
  """An exception raised when the crash cannot be reproduced."""

  MESSAGE = (
      'The crash cannot be reproduced after trying {count} times.\n'
      + UNREPRODUCIBLE_SUGGESTION_TEXT)
  EXIT_CODE = 51

  def __init__(self, count, crash_signatures):
    crash_signatures = [
        {'type': s.crash_type, 'state': s.crash_state_lines,
         'output': s.output[:100000]}
        for s in list(crash_signatures)[:10]
    ]
    super(UnreproducibleError, self).__init__(
        message=self.MESSAGE.format(count=count),
        exit_code=self.EXIT_CODE,
        extras={'signatures': crash_signatures})


class DirtyRepoError(ExpectedException):
  """An exception raised when the repo is dirty. Therefore, we cannot checkout
    to a wanted sha."""

  MESSAGE = (
      "We can't run the checkout command because {source_dir} has "
      'uncommitted changes.\n '
      'please commit or stash these changes and re-run this tool.')
  EXIT_CODE = 52

  def __init__(self, source_dir):
    super(DirtyRepoError, self).__init__(
        self.MESSAGE.format(source_dir=source_dir), self.EXIT_CODE)

class CommandFailedError(ExpectedException):
  """An exception raised when the command doesn't return 0."""

  MESSAGE = '`{cmd}` failed with the return code {returncode}.'
  EXIT_CODE = 53

  def __init__(self, command, returncode, stderr):
    super(CommandFailedError, self).__init__(
        self.MESSAGE.format(cmd=command, returncode=returncode),
        self.EXIT_CODE,
        extras={'stderr': stderr[:100000]})


class KillProcessFailedError(ExpectedException):
  """An exception raised when the process cannot be killed."""

  MESSAGE = '`{command}` (pid={pid}) cannot be killed.'
  EXIT_CODE = 54

  def __init__(self, command, pid):
    super(KillProcessFailedError, self).__init__(
        self.MESSAGE.format(command=command, pid=pid),
        self.EXIT_CODE)


class UserRespondingNoError(ExpectedException):
  """An exception raised when the user decides not to proceed."""

  MESSAGE = 'User responding "no" to "{question}"'
  EXIT_CODE = 55

  def __init__(self, question):
    super(UserRespondingNoError, self).__init__(
        self.MESSAGE.format(question=question),
        self.EXIT_CODE)


class InvalidTestcaseIdError(ExpectedException):
  """An exception when the testcase id is invalid."""

  MESSAGE = (
      'The testcase ID ({testcase_id}) is invalid.\n'
      "Please double-check if there's a typo.\n"
      'Also, can you access '
      'https://clusterfuzz.com/v2/testcase-detail/{testcase_id} ?')
  EXIT_CODE = 56

  def __init__(self, testcase_id):
    super(InvalidTestcaseIdError, self).__init__(
        self.MESSAGE.format(testcase_id=str(testcase_id)), self.EXIT_CODE)


class UnauthorizedError(ExpectedException):
  """An exception when the user cannot access the testcase."""

  MESSAGE = (
      "You aren't allowed to access the testcase ID ({testcase_id}). "
      'Can you access '
      'https://clusterfuzz.com/v2/testcase-detail/{testcase_id} ?')
  EXIT_CODE = 57

  def __init__(self, testcase_id):
    super(UnauthorizedError, self).__init__(
        self.MESSAGE.format(testcase_id=str(testcase_id)), self.EXIT_CODE)


class DifferentStacktraceError(ExpectedException):
  """An exception raised when the resulting crash is different."""

  MESSAGE = (
      'The original crash cannot be reproduced after trying {count} times.\n'
      'But it seems we get a different stacktrace. Could you check if the '
      'stacktrace is good enough?\n\n' + UNREPRODUCIBLE_SUGGESTION_TEXT)
  EXIT_CODE = 58

  def __init__(self, count, crash_signatures):
    crash_signatures = [
        {'type': s.crash_type, 'state': s.crash_state_lines,
         'output': s.output[:50000]}
        for s in list(crash_signatures)[:10]
    ]
    super(DifferentStacktraceError, self).__init__(
        message=self.MESSAGE.format(count=count),
        exit_code=self.EXIT_CODE,
        extras={'signatures': crash_signatures})


class GdbNotSupportedOnAndroidError(ExpectedException):
  """An exception raised when debug is enabled on Android."""

  MESSAGE = "--enable-debug (or gdb) isn't supported in Android."
  EXIT_CODE = 59

  def __init__(self):
    super(GdbNotSupportedOnAndroidError, self).__init__(
        message=self.MESSAGE, exit_code=self.EXIT_CODE)


class BootFailed(ExpectedException):
  """An exception is raised after device failed to complete boot."""

  MESSAGE = (
      'Device failed to finish boot. Please inspect logcat output to '
      'identify the issue.')
  EXIT_CODE = 60

  def __init__(self):
    super(BootFailed, self).__init__(
        message=self.MESSAGE, exit_code=self.EXIT_CODE)


class NoAndroidDeviceIdError(ExpectedException):
  """An exception is raised after installing ASAN on Android"""

  MESSAGE = 'Please set the target Android device ID as the env {env_name}.'
  EXIT_CODE = 61

  def __init__(self, env_name):
    super(NoAndroidDeviceIdError, self).__init__(
        message=self.MESSAGE.format(env_name=env_name),
        exit_code=self.EXIT_CODE)
