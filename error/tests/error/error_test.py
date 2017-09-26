"""Tests for error."""

import collections

from error import error
from test_libs import helpers


class FakeException(error.ExpectedException):
  """FakeException."""

  EXIT_CODE = 100


class AnotherFakeException(error.ExpectedException):
  """AnotherFakeException."""

  EXIT_CODE = 100


class GetClassTest(helpers.ExtendedTestCase):
  """Test get_class."""

  def test_get_by_code(self):
    """Get each class by exit code."""
    self.assertEqual(
        error.MinimizationNotFinishedError,
        error.get_class(error.MinimizationNotFinishedError.EXIT_CODE))
    self.assertEqual(
        error.UserRespondingNoError,
        error.get_class(error.UserRespondingNoError.EXIT_CODE))

  def test_get_unknown(self):
    """Get UnknownException."""
    self.assertEqual(
        error.UnknownExitCodeError, error.get_class(9999))

  def test_same_exit_code(self):
    """Test some classes having the same exit code."""
    helpers.patch(self, ['inspect.getmembers'])
    self.mock.getmembers.return_value = [
        (FakeException.__name__, FakeException),
        (AnotherFakeException.__name__, AnotherFakeException)]

    with self.assertRaises(Exception) as cm:
      error.get_class(500)

    self.assertEqual(
        'FakeException and AnotherFakeException have the same exit code.',
        cm.exception.message)


Signature = collections.namedtuple(
    'Signature', ['crash_type', 'crash_state_lines', 'output'])


class InitTest(helpers.ExtendedTestCase):
  """Test initialize all types of Exception."""

  def test_init(self):
    """Test init."""
    error.MinimizationNotFinishedError()
    error.SanitizerNotProvidedError()
    error.ClusterFuzzError(500, 'resp', 'identity')
    error.PermissionsTooPermissiveError('filename', 'perm')
    error.GomaNotInstalledError()
    error.JobTypeNotSupportedError('job', '1234')
    error.NotInstalledError('bin')
    error.GsutilNotInstalledError()
    error.BadJobTypeDefinitionError('job')
    error.UnreproducibleError(10, [Signature('type', ['a', 'b'], 'output')])
    error.DirtyRepoError('source')
    error.CommandFailedError('cmd', 12, 'err')
    error.KillProcessFailedError('cmd', 123)
    error.UserRespondingNoError('question')
    error.InvalidTestcaseIdError('123456')
    error.UnauthorizedError('123456', 'identity')
    error.DifferentStacktraceError(
        10, [Signature('type', ['a', 'b'], 'output')])
    error.GdbNotSupportedOnAndroidError()
    error.BootFailed()
    error.NoAndroidDeviceIdError('ANDROID_SERIAL')
    error.GclientManagedEnabledException('/chromium/.gclient')
