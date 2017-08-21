"""Tests the android module."""
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
import mock

from clusterfuzz import android
from error import error
from test_libs import helpers


class AdbTest(helpers.ExtendedTestCase):
  """Tests adb."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_adb(self):
    """Tests adb."""
    self.mock.execute.return_value = (0, 'output')
    self.assertEqual((0, 'output'), android.adb('test', print_command=True))
    self.mock.execute.assert_called_once_with(
        'adb', 'test', cwd='.', print_command=True)


class AdbShellTest(helpers.ExtendedTestCase):
  """Tests adb_shell."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.adb'])

  def test_adb_shell(self):
    """Tests adb_shell."""
    self.mock.adb.return_value = (0, 'output')
    self.assertEqual(
        (0, 'output'),
        android.adb_shell('test "so\\mething"', print_command=True))
    self.mock.adb.assert_called_once_with(
        'shell "test \\"so\\\\mething\\""', print_command=True)


class WriteContentTest(helpers.ExtendedTestCase):
  """Tests write_content."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb',
        'clusterfuzz.android.adb_shell',
        'clusterfuzz.common.delete_if_exists',
        'tempfile.NamedTemporaryFile',
    ])

  def test_write(self):
    """Tests write_content."""
    # name is a special attribute in mock.Mock. Therefore, it needs a special
    # way of mocking.
    tmp_file = mock.Mock()
    type(tmp_file).name = mock.PropertyMock(return_value='/tmp/file')

    tmp = mock.Mock()
    tmp.__enter__ = mock.Mock(return_value=tmp_file)
    tmp.__exit__ = mock.Mock(return_value=False)
    self.mock.NamedTemporaryFile.return_value = tmp

    android.write_content('/test.html', 'content')

    self.mock.NamedTemporaryFile.assert_called_once_with(delete=False)
    self.mock.adb.assert_called_once_with('push /tmp/file /test.html')
    self.mock.adb_shell.assert_called_once_with('chmod 0644 /test.html')
    self.mock.delete_if_exists.assert_called_once_with('/tmp/file')
    tmp_file.write.assert_called_once_with('content')


class EnsureAsanTest(helpers.ExtendedTestCase):
  """Tests ensure_asan."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.reboot',
        'clusterfuzz.common.check_confirm',
        'clusterfuzz.common.check_binary',
        'clusterfuzz.common.execute',
        'clusterfuzz.common.get_resource',
    ])
    self.mock.get_resource.return_value = 'setup.sh'
    self.mock.check_binary.return_value = 'adb'

  def test_no_setup(self):
    """Tests no setup."""
    self.mock.execute.return_value = (
        0, 'blah\nThe device is up-to-date.\nblah')
    android.ensure_asan('lib_path', 'device')

    self.mock.check_confirm.assert_called_once_with(mock.ANY)
    self.mock.execute.assert_called_once_with(
        'setup.sh',
        ('--lib lib_path --device device'),
        env={'ADB_PATH': 'adb'},
        redirect_stderr_to_stdout=True,
        cwd='.')

  def test_setup(self):
    """Tests setup ASAN."""
    self.mock.get_resource.return_value = 'setup.sh'
    self.mock.check_binary.return_value = 'adb'
    self.mock.execute.return_value = (
        0, 'blah\n%s\nblah' % android.ASAN_BEING_INSTALLED_SEARCH_STRING)

    android.ensure_asan('lib_path', 'device')

    self.mock.check_confirm.assert_called_once_with(mock.ANY)
    self.mock.execute.assert_called_once_with(
        'setup.sh',
        ('--lib lib_path --device device'),
        env={'ADB_PATH': 'adb'},
        redirect_stderr_to_stdout=True,
        cwd='.')
    self.mock.reboot.assert_called_once_with()


class EnsureActiveTest(helpers.ExtendedTestCase):
  """Tests ensure_active."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb_shell',
        'time.sleep',
    ])

  def test_ensure(self):
    """Tests ensure_active."""
    self.mock.adb_shell.return_value = (0, '')
    android.ensure_active()

    self.assert_exact_calls(self.mock.adb_shell, [
        mock.call('dumpsys window', print_command=False, print_output=False),
        mock.call('input keyevent KEYCODE_POWER', print_command=False,
                  print_output=False),
        mock.call('input keyevent KEYCODE_POWER', print_command=False,
                  print_output=False),
        mock.call('input keyevent KEYCODE_POWER', print_command=False,
                  print_output=False),
        mock.call('input keyevent KEYCODE_MENU', print_command=False,
                  print_output=False),
    ])


class SetContentSettingTest(helpers.ExtendedTestCase):
  """Tests set content."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb_shell'
    ])

  def test_set(self):
    """Tests set."""
    android.set_content_setting('table', 'key', 'value')
    self.mock.adb_shell.assert_called_once_with(
        'content insert --uri content://table --bind name:s:key --bind '
        'value:value',
        print_command=False,
        print_output=False)


class RebootTest(helpers.ExtendedTestCase):
  """Tests reboot."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb',
        'clusterfuzz.android.wait_until_fully_booted'
    ])

  def test_ensure(self):
    """Tests ensure."""
    android.reboot()
    self.assert_exact_calls(self.mock.adb, [
        mock.call('reboot')])
    self.mock.wait_until_fully_booted.assert_called_once_with()


class WaitUntilFullyBooted(helpers.ExtendedTestCase):
  """Tests wait_until_fully_booted."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb',
        'time.time'
    ])

  def test_boot_completed(self):
    """Tests boot completed."""
    self.mock.time.side_effect = [1, 5]
    self.mock.adb.side_effect = [
        (0, ''),
        (0, '0\n'),
        (0, 'package:/system/framework/framework-res.apk\n'),
        (0, '1\n')]
    self.assertTrue(android.wait_until_fully_booted())


  def test_boot_failed(self):
    """Tests boot completed."""
    self.mock.time.side_effect = [1, 601]

    with self.assertRaises(error.BootFailed):
      android.wait_until_fully_booted()

    self.assert_exact_calls(self.mock.adb, [
        mock.call('wait-for-device')])


class EnsureRootAndRemountTest(helpers.ExtendedTestCase):
  """Tests ensure_root."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb'
    ])

  def test_ensure(self):
    """Tests ensure."""
    android.ensure_root_and_remount()
    self.assert_exact_calls(self.mock.adb, [
        mock.call('root'), mock.call('remount')
    ])


class ResetTest(helpers.ExtendedTestCase):
  """Tests reset."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb_shell',
        'clusterfuzz.android.set_content_setting'
    ])

  def test_ensure(self):
    """Tests ensure."""
    android.reset('package')
    self.assert_exact_calls(self.mock.adb_shell, [
        mock.call('pm clear package'),
        mock.call('pm grant package android.permission.READ_EXTERNAL_STORAGE',
                  print_command=False, print_output=False),
        mock.call('pm grant package android.permission.WRITE_EXTERNAL_STORAGE',
                  print_command=False, print_output=False)
    ])
    self.assert_exact_calls(self.mock.set_content_setting, [
        mock.call(
            'com.google.settings/partner', 'use_location_for_services', 'i:0'),
        mock.call('settings/global', 'assisted_gps_enabled', 'i:0'),
        mock.call('settings/global', 'development_settings_enabled', 'i:0'),
        mock.call('settings/global', 'stay_on_while_plugged_in', 'i:3'),
        mock.call('settings/global', 'send_action_app_error', 'i:0'),
        mock.call('settings/global', 'verifier_verify_adb_installs', 'i:0'),
        mock.call('settings/global', 'wifi_scan_always_enabled', 'i:0'),
        mock.call('settings/secure', 'anr_show_background', 'i:0'),
        mock.call('settings/secure', 'doze_enabled', 'i:0'),
        mock.call('settings/secure', 'location_providers_allowed', 's:'),
        mock.call('settings/secure', 'lockscreen.disabled', 'i:1'),
        mock.call('settings/secure', 'screensaver_enabled', 'i:0'),
        mock.call('settings/system', 'accelerometer_rotation', 'i:0'),
        mock.call('settings/system', 'auto_time', 'i:0'),
        mock.call('settings/system', 'auto_timezone', 'i:0'),
        mock.call('settings/system', 'lockscreen.disabled', 'i:1'),
        mock.call('settings/system', 'notification_light_pulse', 'i:0'),
        mock.call('settings/system', 'screen_brightness_mode', 'i:0'),
        mock.call('settings/system', 'screen_brightness', 'i:255'),
        mock.call('settings/system', 'user_rotation', 'i:0'),
    ])


class ClearLogTest(helpers.ExtendedTestCase):
  """Tests clear_log."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.adb'])

  def test_clear(self):
    """Tests clear_log."""
    android.clear_log()
    self.mock.adb.assert_called_once_with('logcat -c')


class GetLogTest(helpers.ExtendedTestCase):
  """Tests get_log."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.adb'])

  def test_clear(self):
    """Tests clear_log."""
    self.mock.adb.return_value = (0, 'log')
    self.assertEqual('log', android.get_log())
    self.mock.adb.assert_called_once_with(
        'logcat -d -v brief *:I', redirect_stderr_to_stdout=True,
        stdout_transformer=mock.ANY)


class KillTest(helpers.ExtendedTestCase):
  """Tests kill."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb_shell',
        'clusterfuzz.android.ensure_active'
    ])

  def test_kill(self):
    """Tests kill."""
    android.kill('package')

    self.assert_exact_calls(self.mock.adb_shell, [
        mock.call('am force-stop package', exit_on_error=False),
        mock.call('input keyevent 66', print_command=False, print_output=False),
    ])
    self.mock.ensure_active.assert_called_once_with()


class ConvertChromeCrashStackLineTest(helpers.ExtendedTestCase):
  """Tests convert_chrome_crash_stack_line."""

  def test_ignore(self):
    """Tests ignoring a line."""
    self.assertIsNone(android.convert_chrome_crash_stack_line('SAWEgwwegweg'))

  def test_convert(self):
    """Tests converting Chrome crash stack line."""
    self.assertEqual(
        '    #12 0xcde (binary+0xabc)',
        android.convert_chrome_crash_stack_line(' #12 0xcde binary+0xabc'))
    self.assertEqual(
        ('    #47 0x6a60e37f '
         '(/data/app/org.chromium.chrome-2/lib/arm/libchrome.so+0x0ad7237f)'),
        android.convert_chrome_crash_stack_line(
            ' #47 0x6a60e37f '
            '/data/app/org.chromium.chrome-2/lib/arm/libchrome.so+0x0ad7237f'))


class ConvertAndroidCrashStackLineTest(helpers.ExtendedTestCase):
  """Tests convert_android_crash_stack_line."""

  def test_ignore(self):
    """Tests ignoring a line."""
    self.assertIsNone(android.convert_android_crash_stack_line('SAWEgwwegweg'))

  def test_convert(self):
    """Tests converting Chrome crash stack line."""
    self.assertEqual(
        '    #12 0xabc (binary+0xabc)',
        android.convert_android_crash_stack_line(' #12 pc abc binary'))
    self.assertEqual(
        ('    #62 0x064b9d51 '
         '(/data/app/org.chromium.chrome-2/lib/arm/libchrome.so+0x064b9d51)'),
        android.convert_android_crash_stack_line(
            '     #62 pc 064b9d51  '
            '/data/app/org.chromium.chrome-2/lib/arm/libchrome.so'))


class GetProcessIdAndNameTest(helpers.ExtendedTestCase):
  """Tests get_process_id_and_name."""

  def test_ignore(self):
    """Tests ignoring a line."""
    self.assertIsNone(android.get_process_id_and_name('asdfkljweflkj'))

  def test_get(self):
    """Tests getting."""
    self.assertEqual(
        (12882, 'chromium'),
        android.get_process_id_and_name('chromium(12882)'))
    self.assertEqual(
        (372, 'DEBUG'), android.get_process_id_and_name('DEBUG   (  372)'))


class FilterLogTest(helpers.ExtendedTestCase):
  """Tests filter_log."""

  def test_empty(self):
    """Tests filtering empty content."""
    self.assertEqual('', android.filter_log(''))

  def test_filter(self):
    """Tests filtering."""
    self.assertEqual(
        ('--------- chromium (12882):\n'
         'random line\n'
         '    #31 0x6a57caa3 '
         '(/data/app/org.chromium.chrome-2/lib/arm/libchrome.so+0x0ace0aa3)\n'
         '--------- DEBUG (372):\n'
         '    #21 0x0ace0211 '
         '(/data/app/org.chromium.chrome-2/lib/arm/libchrome.so+0x0ace0211)\n'
         '    #21 pc 0ace0211  <unknown>\n'),
        android.filter_log(
            'invalid line\n'
            'F/chromium(12882): random line\n'
            'F/chromium(12882): #31 0x6a57caa3 '
            '/data/app/org.chromium.chrome-2/lib/arm/libchrome.so+0x0ace0aa3\n'
            'F/DEBUG   (  372):     #21 pc 0ace0211  '
            '/data/app/org.chromium.chrome-2/lib/arm/libchrome.so\n'
            'F/DEBUG   (  372):     #21 pc 0ace0211  <unknown>\n'))


class InstallTest(helpers.ExtendedTestCase):
  """Tests android.install."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.adb'])

  def test_succeed(self):
    """Tests installing successfully."""
    self.mock.adb.return_value = (0, 'success')
    self.assertEqual((0, 'success'), android.install('apk'))

    self.mock.adb.assert_called_once_with(
        'install -r apk', redirect_stderr_to_stdout=True)

  def test_failure(self):
    """Tests failure."""
    self.mock.adb.return_value = (0, 'Failure')
    with self.assertRaises(error.CommandFailedError):
      android.install('apk')
    self.mock.adb.assert_called_once_with(
        'install -r apk', redirect_stderr_to_stdout=True)

  def test_failed(self):
    """Tests failure."""
    self.mock.adb.return_value = (0, 'Failed')
    with self.assertRaises(error.CommandFailedError):
      android.install('apk')
    self.mock.adb.assert_called_once_with(
        'install -r apk', redirect_stderr_to_stdout=True)


class FixLibPathTest(helpers.ExtendedTestCase):
  """Tests fix_lib_path."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.find_lib_path'])

  def test_fix(self):
    """Tests fix."""
    self.mock.find_lib_path.return_value = 'replaced'
    content = (
        'random line\n'
        '    #15 0x1234 (/android/libchrome.so+0x4566)\n'
        '    #16 0x777 (/android/libhwu.so+0x999)\n')
    self.assertEqual(
        ('random line\n'
         '    #15 0x1234 (replaced+0x4566)\n'
         '    #16 0x777 (replaced+0x999)'),
        android.fix_lib_path(content, ['/search'], '/tmp'))
    self.assert_exact_calls(self.mock.find_lib_path, [
        mock.call('/android/libchrome.so', ['/search'], '/tmp'),
        mock.call('/android/libhwu.so', ['/search'], '/tmp'),
    ])


class FindLibPathTest(helpers.ExtendedTestCase):
  """Tests find_lib_path."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.adb'])
    self.setup_fake_filesystem()

    os.makedirs('/test/lib')
    os.makedirs('/tmp/lib')

  def test_find(self):
    """Tests finding lib in search_paths."""
    self.fs.CreateFile('/test/lib/libc.so')
    self.fs.CreateFile('/tmp/lib/libchrome.so')
    self.assertEqual(
        '/test/lib/libc.so',
        android.find_lib_path('/android/libc.so', ['/test/lib'], '/tmp/lib'))
    self.assertEqual(
        '/tmp/lib/libchrome.so',
        android.find_lib_path(
            '/android/libchrome.so', ['/test/lib'], '/tmp/lib'))
    self.assertEqual(0, self.mock.adb.call_count)

  def test_pull(self):
    """Tests pulling from android."""
    self.mock.adb.side_effect = (
        lambda _: self.fs.CreateFile('/tmp/lib/libc.so', contents='test'))
    self.assertEqual(
        '/tmp/lib/libc.so',
        android.find_lib_path('/android/libc.so', ['/test/lib'], '/tmp/lib'))
    self.assert_exact_calls(self.mock.adb, [
        mock.call('pull /android/libc.so /tmp/lib'),
    ])

  def test_pull_exception(self):
    """Tests failing to pull."""
    with self.assertRaises(Exception):
      android.find_lib_path('/android/libc.so', ['/test/lib'], '/tmp/lib')
    self.assert_exact_calls(self.mock.adb, [
        mock.call('pull /android/libc.so /tmp/lib'),
    ])
