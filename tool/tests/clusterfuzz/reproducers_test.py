"""Test the reproducers."""
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
import json
import mock

from clusterfuzz import common
from clusterfuzz import output_transformer
from clusterfuzz import reproducers
from error import error
from tests import libs
from test_libs import helpers


def create_reproducer(klass):
  """Creates a LinuxChromeJobReproducer for use in testing."""

  binary_provider = mock.Mock(symbolizer_path='/path/to/symbolizer')
  binary_provider.get_binary_path.return_value = '/fake/build_dir/test_binary'
  binary_provider.get_build_dir_path.return_value = '/fake/build_dir'
  testcase = mock.Mock(
      gestures=None,
      stacktrace_lines=[{
          'content': 'line'
      }],
      job_type='job_type',
      reproduction_args='--original',
      android_package_name='package')
  testcase.get_testcase_path.return_value = '/fake/testcase_dir/testcase'
  reproducer = klass(
      definition=mock.Mock(),
      binary_provider=binary_provider,
      testcase=testcase,
      sanitizer='UBSAN',
      options=libs.make_options(target_args='--test'))
  reproducer.args = '--always-opt'
  reproducer.environment = {}
  reproducer.source_directory = '/fake/source_dir'
  reproducer.original_testcase_path = '/fake/original_testcase_dir/testcase'
  return reproducer


class SetUpSymbolizersSuppressionsTest(helpers.ExtendedTestCase):
  """Tests the set_up_symbolizers_suppressions method."""

  def setUp(self):
    self.setup_fake_filesystem()
    helpers.patch(self, ['clusterfuzz.common.get_resource'])

  def test_set_up_correct_env(self):
    """Ensures all the setup methods work correctly."""
    root_path = '/fake'
    self.fs.CreateFile('/fake/resources/llvm-symbolizer', contents='t')
    self.fs.CreateFile(
        '/fake/resources/suppressions/lsan_suppressions.txt', contents='t')
    self.fs.CreateFile(
        '/fake/resources/suppressions/ubsan_suppressions.txt', contents='t')

    def get(_, *paths):
      return os.path.join(root_path, *paths)

    self.mock.get_resource.side_effect = get

    self.binary_provider = mock.Mock()
    self.definition = mock.Mock()
    self.testcase = mock.Mock(
        gestures=None,
        stacktrace_lines=[{
            'content': 'line'
        }],
        job_type='job_type',
        reproduction_args='--orig')
    self.reproducer = reproducers.BaseReproducer(
        self.definition,
        self.binary_provider,
        self.testcase,
        'UBSAN',
        libs.make_options(target_args='--test'))

    self.reproducer.environment = {
        'UBSAN_OPTIONS': ('external_symbolizer_path=/not/correct/path:other_'
                          'option=1:suppressions=/not/correct/path:'
                          'coverage_dir=test'),
        'CFI_OPTIONS': ('external_symbolizer_path=/not/correct/path:other_'
                        'option=1:suppressions=/not/correct/path'),
        'LSAN_OPTIONS':
            'other=0:suppressions=not/correct/path:option=1'
    }
    self.reproducer.set_up_symbolizers_suppressions()
    result = self.reproducer.environment
    for i in result:
      if '_OPTIONS' in i:
        result[i] = reproducers.deserialize_sanitizer_options(result[i])
    self.assertEqual(
        result, {
            'UBSAN_OPTIONS': {
                'external_symbolizer_path':
                    '%s/resources/llvm-symbolizer' % root_path,
                'other_option':
                    '1',
                'suppressions': (
                    '%s/resources/suppressions/ubsan_suppressions.txt' %
                    root_path)
            },
            'CFI_OPTIONS': {
                'external_symbolizer_path':
                    '%s/resources/llvm-symbolizer' % root_path,
                'other_option':
                    '1',
                'suppressions': (
                    '%s/resources/suppressions/ubsan_suppressions.txt' %
                    root_path)
            },
            'LSAN_OPTIONS': {
                'other':
                    '0',
                'suppressions': (
                    '%s/resources/suppressions/lsan_suppressions.txt' %
                    root_path),
                'option':
                    '1'
            },
            'UBSAN_SYMBOLIZER_PATH':
                '%s/resources/llvm-symbolizer' % root_path,
            'DISPLAY':
                ':0.0'
        })


class SanitizerOptionsSerializerTest(helpers.ExtendedTestCase):
  """Test the serializer & deserializers for sanitizer options."""

  def test_serialize(self):
    in_dict = {
        'suppressions': '/a/b/c/d/suppresions.txt',
        'option': '1',
        'symbolizer': 'abcde/llvm-symbolizer'
    }
    out_str = ('suppressions=/a/b/c/d/suppresions.txt:option=1'
               ':symbolizer=abcde/llvm-symbolizer')

    self.assertEqual(reproducers.serialize_sanitizer_options(in_dict), out_str)

  def test_deserialize(self):
    out_dict = {
        'suppressions': '/a/b/c/d/suppresions.txt',
        'option': '1',
        'symbolizer': 'abcde/llvm-symbolizer'
    }
    in_str = ('suppressions=/a/b/c/d/suppresions.txt:option=1'
              ':symbolizer=abcde/llvm-symbolizer')

    self.assertEqual(
        reproducers.deserialize_sanitizer_options(in_str), out_dict)


class ReproduceCrashTest(helpers.ExtendedTestCase):
  """Tests the reproduce_crash method."""

  def setUp(self):
    self.setup_fake_filesystem()
    helpers.patch(self, [
        'clusterfuzz.common.start_execute',
        'clusterfuzz.common.wait_execute',
        'clusterfuzz.common.execute',
        'clusterfuzz.common.UserStdin',
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.run_gestures',
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.get_testcase_path',
        'clusterfuzz.reproducers.Xvfb.__enter__',
        'clusterfuzz.reproducers.Xvfb.__exit__',
        'clusterfuzz.reproducers.symbolize',
        'clusterfuzz.common.get_resource',
    ])
    self.mock.get_resource.return_value = (
        '/chrome/source/folder/llvm-symbolizer')
    self.mock.wait_execute.return_value = (0, 'lines')
    self.mock.symbolize.return_value = 'symbolized'
    self.app_directory = '/chrome/source/folder'
    self.testcase_path = os.path.expanduser(
        os.path.join('~', '.clusterfuzz', '1234_testcase', 'testcase.js'))
    self.mock.get_testcase_path.return_value = self.testcase_path
    self.definition = mock.Mock()

  def test_base(self):
    """Test base's reproduce_crash."""

    mocked_testcase = mock.Mock(
        id=1234,
        reproduction_args='--repro',
        environment={'ASAN_OPTIONS': 'test-asan'},
        gestures=None,
        stacktrace_lines=[{
            'content': 'line'
        }],
        job_type='job_type')
    mocked_testcase.get_testcase_path.return_value = self.testcase_path
    mocked_provider = mock.Mock(
        symbolizer_path='%s/llvm-symbolizer' % self.app_directory)
    mocked_provider.get_binary_path.return_value = '%s/d8' % self.app_directory
    mocked_provider.get_build_dir_path.return_value = self.app_directory

    reproducer = reproducers.BaseReproducer(
        self.definition,
        mocked_provider,
        mocked_testcase,
        'UBSAN',
        libs.make_options(target_args='--test'))
    reproducer.setup_args()
    reproducer.reproduce_crash()
    self.assert_exact_calls(self.mock.execute, [
        mock.call(
            '/chrome/source/folder/d8',
            '--repro --test %s' % self.testcase_path,
            '/chrome/source/folder',
            env={'ASAN_OPTIONS': 'test-asan'},
            exit_on_error=False,
            timeout=30,
            stdout_transformer=mock.ANY,
            redirect_stderr_to_stdout=True,
            stdin=self.mock.UserStdin.return_value,
            read_buffer_length=1)
    ])

  def test_base_with_env_args(self):
    """Test base's reproduce_crash with environment args."""

    mocked_testcase = mock.Mock(
        id=1234,
        reproduction_args='--app-dir=%APP_DIR% --testcase=%TESTCASE%',
        environment={'ASAN_OPTIONS': 'test-asan'},
        gestures=None,
        stacktrace_lines=[{
            'content': 'line'
        }],
        job_type='job_type')
    mocked_testcase.get_testcase_path.return_value = self.testcase_path
    mocked_provider = mock.Mock(
        symbolizer_path='%s/llvm-symbolizer' % self.app_directory)
    mocked_provider.get_binary_path.return_value = '%s/d8' % self.app_directory
    mocked_provider.get_build_dir_path.return_value = self.app_directory

    reproducer = reproducers.BaseReproducer(
        self.definition,
        mocked_provider,
        mocked_testcase,
        'UBSAN',
        libs.make_options(target_args='--test'))
    reproducer.setup_args()
    reproducer.reproduce_crash()
    self.assert_exact_calls(self.mock.execute, [
        mock.call(
            '/chrome/source/folder/d8',
            '--app-dir=%s --testcase=%s --test' %
            (self.app_directory, self.testcase_path),
            '/chrome/source/folder',
            env={'ASAN_OPTIONS': 'test-asan'},
            exit_on_error=False,
            timeout=30,
            stdout_transformer=mock.ANY,
            redirect_stderr_to_stdout=True,
            stdin=self.mock.UserStdin.return_value,
            read_buffer_length=1)
    ])

  def test_chromium(self):
    """Test chromium's reproduce_crash."""

    self.mock.start_execute.return_value = mock.Mock()
    self.mock.__enter__.return_value = ':display'
    mocked_testcase = mock.Mock(
        id=1234,
        reproduction_args='--repro',
        environment={'ASAN_OPTIONS': 'test-asan'},
        gestures=None,
        stacktrace_lines=[{
            'content': 'line'
        }],
        job_type='job_type')
    mocked_testcase.get_testcase_path.return_value = self.testcase_path
    mocked_provider = mock.Mock(
        symbolizer_path='%s/llvm-symbolizer' % self.app_directory)
    mocked_provider.get_binary_path.return_value = '%s/d8' % self.app_directory
    mocked_provider.get_build_dir_path.return_value = self.app_directory

    reproducer = reproducers.LinuxChromeJobReproducer(
        self.definition,
        mocked_provider,
        mocked_testcase,
        'UBSAN',
        libs.make_options(target_args='--test'))
    reproducer.gestures = ['gesture,1', 'gesture,2']
    reproducer.setup_args()
    err, text = reproducer.reproduce_crash()
    self.assertEqual(err, 0)
    self.assertEqual(text, 'symbolized')
    self.assert_exact_calls(self.mock.start_execute, [
        mock.call(
            '/chrome/source/folder/d8',
            '--repro --test %s' % self.testcase_path,
            '/chrome/source/folder',
            env={
                'DISPLAY': ':display',
                'ASAN_OPTIONS': 'test-asan',
            },
            redirect_stderr_to_stdout=True,
            stdin=self.mock.UserStdin.return_value)
    ])
    self.assert_exact_calls(self.mock.wait_execute, [
        mock.call(
            self.mock.start_execute.return_value,
            exit_on_error=False,
            timeout=30,
            stdout_transformer=mock.ANY,
            read_buffer_length=1)
    ])
    self.assert_exact_calls(self.mock.run_gestures, [
        mock.call(reproducer, self.mock.start_execute.return_value, ':display')
    ])


class SetupArgsTest(helpers.ExtendedTestCase):
  """Test setup_args."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.edit_if_needed',
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.get_testcase_path',
        'clusterfuzz.reproducers.update_for_gdb_if_needed',
    ])
    self.testcase = mock.Mock(
        id=1234,
        reproduction_args='--repro',
        environment={'ASAN_OPTIONS': 'test-asan'},
        gestures=None,
        stacktrace_lines=[{
            'content': 'line'
        }],
        job_type='job_type')
    self.testcase_path = os.path.expanduser(
        os.path.join('~', '.clusterfuzz', '1234_testcase', 'testcase.js'))
    self.mock.get_testcase_path.return_value = self.testcase_path
    self.provider = mock.Mock(
        symbolizer_path='/chrome/source/folder/llvm-symbolizer')
    self.provider.get_binary_path.return_value = '/chrome/source/folder/d8'
    self.provider.get_build_dir_path.return_value = '/chrome/source/folder'
    self.definition = mock.Mock()
    self.mock.update_for_gdb_if_needed.side_effect = (
        lambda binary_path, args, timeout, should_enable_gdb: (binary_path, args, timeout)
    )
    self.mock.edit_if_needed.side_effect = (
        lambda content, prefix, comment, should_edit: content)

  def test_disable_xvfb(self):
    """Test disable xvfb."""
    reproducer = reproducers.LinuxChromeJobReproducer(
        self.definition, self.provider, self.testcase, 'UBSAN',
        libs.make_options(
            disable_xvfb=True,
            target_args='--test --disable-gl-drawing-for-tests'))
    reproducer.args = '--repro %TESTCASE_FILE_URL%'

    reproducer.setup_args()
    self.assertEqual('--repro %s --test' % self.testcase_path, reproducer.args)
    self.mock.update_for_gdb_if_needed.assert_called_once_with(
        reproducer.binary_path, reproducer.args, reproducer.timeout,
        reproducer.options.enable_debug)
    self.mock.edit_if_needed.assert_called_once_with(
        reproducer.args,
        prefix=mock.ANY,
        comment=mock.ANY,
        should_edit=reproducer.options.edit_mode)

  def test_enable_xvfb(self):
    """Test enable xvfb and edit args."""
    reproducer = reproducers.LinuxChromeJobReproducer(
        self.definition, self.provider, self.testcase, 'UBSAN',
        libs.make_options(target_args='--test', edit_mode=True))

    reproducer.setup_args()
    self.assertEqual('--repro --test %s' % self.testcase_path, reproducer.args)
    self.mock.update_for_gdb_if_needed.assert_called_once_with(
        reproducer.binary_path, reproducer.args, reproducer.timeout,
        reproducer.options.enable_debug)
    self.mock.edit_if_needed.assert_called_once_with(
        reproducer.args,
        prefix=mock.ANY,
        comment=mock.ANY,
        should_edit=reproducer.options.edit_mode)


class LinuxChromeJobReproducerTest(helpers.ExtendedTestCase):
  """Tests the extra functions of LinuxUbsanChromeReproducer."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.reproducers.BaseReproducer.pre_build_steps',
        'clusterfuzz.reproducers.ensure_user_data_dir_if_needed',
        'clusterfuzz.reproducers.update_testcase_path_in_layout_test',
        'clusterfuzz.common.get_resource',
        'pyfakefs.fake_filesystem.FakeFilesystem.RenameObject',
    ])
    self.mock.get_resource.return_value = 'llvm'
    self.mock.ensure_user_data_dir_if_needed.side_effect = (
        lambda args, require_user_data_dir: args + ' --test-user-data-dir')
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)
    self.reproducer.definition.require_user_data_dir = False
    self.reproducer.original_testcase_path = '/fake/LayoutTests/testcase'

  def test_reproduce_crash(self):
    """Ensures pre-build steps run correctly."""
    self.reproducer.pre_build_steps()
    self.assert_exact_calls(self.mock.pre_build_steps,
                            [mock.call(self.reproducer)])
    self.assertEqual(self.reproducer.args, '--always-opt --test-user-data-dir')
    self.mock.ensure_user_data_dir_if_needed.assert_called_once_with(
        '--always-opt', False)

  def test_get_testcase_path(self):
    """Tests get_testcase_path."""
    self.mock.update_testcase_path_in_layout_test.return_value = 'new-path'
    self.assertEqual('new-path', self.reproducer.get_testcase_path())
    self.mock.update_testcase_path_in_layout_test.assert_called_once_with(
        self.reproducer.testcase.get_testcase_path(),
        self.reproducer.original_testcase_path,
        self.reproducer.source_directory, self.reproducer.testcase.created_at)


class XdotoolCommandTest(helpers.ExtendedTestCase):
  """Tests the xdotool_command method."""

  def setUp(self):
    helpers.patch(
        self, ['clusterfuzz.common.execute', 'clusterfuzz.common.BlockStdin'])
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)

  def test_call(self):
    """Tests calling the method."""

    self.reproducer.xdotool_command('command to run', ':2753')
    self.assert_exact_calls(self.mock.execute, [
        mock.call(
            'xdotool',
            'command to run',
            '.',
            env={'DISPLAY': ':2753'},
            stdin=self.mock.BlockStdin.return_value)
    ])


class FindWindowsForProcessTest(helpers.ExtendedTestCase):
  """Tests the find_windows_for_process method."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.get_process_ids',
        'clusterfuzz.common.execute', 'time.sleep'
    ])
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)

  def test_no_pids(self):
    """Tests when no PIDs are available."""

    self.mock.get_process_ids.return_value = []

    self.reproducer.find_windows_for_process(1234, ':45434')
    self.assert_n_calls(0, [self.mock.execute])

  def test_dedup_pids(self):
    """Tests when duplicate pids are introduced."""

    self.mock.get_process_ids.return_value = [1234, 5678]
    self.mock.execute.side_effect = [(0, '234\n567\nabcd\n890'),
                                     (0, '123\n567\n345')]

    result = self.reproducer.find_windows_for_process(1234, ':45434')
    self.assertEqual(result, set(['234', '567', '890', '123', '345']))
    self.assert_exact_calls(self.mock.sleep, [mock.call(30)])


class GetProcessIdsTest(helpers.ExtendedTestCase):
  """Tests the get_process_ids method."""

  def setUp(self):
    helpers.patch(self, ['psutil.Process', 'psutil.pid_exists'])
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)

  def test_process_not_running(self):
    """Tests exiting when psutil is not supported."""
    self.mock.pid_exists.return_value = False

    result = self.reproducer.get_process_ids(1234)
    self.assertEqual(result, [])
    self.assert_n_calls(0, [self.mock.Process])

  def test_psutil_working(self):
    """Tests grabbing process IDs when process is running."""

    self.mock.pid_exists.return_value = True
    psutil_handle = mock.Mock()
    psutil_handle.children.return_value = [
        mock.Mock(pid=123), mock.Mock(pid=456)
    ]
    self.mock.Process.return_value = psutil_handle

    result = self.reproducer.get_process_ids(1234)
    self.assertEqual(result, [1234, 123, 456])

  def _raise(self, _):
    raise Exception('Oops')

  def test_exception_handling(self):
    """Tests functionality when an exception is raised."""

    self.mock.Process.side_effect = self._raise

    with self.assertRaises(Exception):
      self.reproducer.get_process_ids(1234)


class RunGesturesTest(helpers.ExtendedTestCase):
  """Tests the run_gestures method."""

  def setUp(self):
    helpers.patch(self, [
        'time.sleep',
        ('clusterfuzz.reproducers.LinuxChromeJobReproducer.get_gesture_start_'
         'time'),
        ('clusterfuzz.reproducers.LinuxChromeJobReproducer.find_windows_for'
         '_process'),
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.xdotool_command',
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.execute_gesture'
    ])
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)
    self.mock.get_gesture_start_time.return_value = 5
    self.mock.find_windows_for_process.return_value = ['123']
    self.reproducer.gestures = [
        'windowsize,2', 'type,\'ValeM1khbW4Gt!\'', 'Trigger:2'
    ]
    self.reproducer.gesture_start_time = 5

  def test_execute_gestures(self):
    """Tests executing the gestures."""

    self.reproducer.run_gestures(mock.Mock(pid=1234), ':display')

    self.assert_exact_calls(
        self.mock.xdotool_command,
        [mock.call(self.reproducer, 'windowactivate --sync 123', ':display')])
    self.assert_exact_calls(self.mock.sleep, [mock.call(5)])


class GetGestureStartTimeTest(helpers.ExtendedTestCase):
  """Test the get_gesture_start_time method."""

  def setUp(self):
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)

  def test_with_trigger(self):
    self.reproducer.gestures = [
        'windowsize,2', 'type,\'ValeM1khbW4Gt!\'', 'Trigger:2'
    ]
    result = self.reproducer.get_gesture_start_time()
    self.assertEqual(result, 2)

  def test_no_trigger(self):
    self.reproducer.gestures = ['windowsize,2', 'type,\'ValeM1khbW4Gt!\'']
    result = self.reproducer.get_gesture_start_time()
    self.assertEqual(result, 5)


class ExecuteGestureTest(helpers.ExtendedTestCase):
  """Test the execute_gesture method."""

  def setUp(self):
    helpers.patch(
        self,
        ['clusterfuzz.reproducers.LinuxChromeJobReproducer.xdotool_command'])
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)
    self.reproducer.gestures = ['windowsize,2', 'type,\'ValeM1khbW4Gt!\'']

  def test_call_execute_gesture(self):
    """Test parsing gestures."""

    for gesture in self.reproducer.gestures:
      self.reproducer.execute_gesture(gesture, '12345', ':display')

    self.assert_exact_calls(self.mock.xdotool_command, [
        mock.call(self.reproducer, 'windowsize 12345 2', ':display'),
        mock.call(self.reproducer, 'type -- \'ValeM1khbW4Gt!\'', ':display')
    ])


class XvfbTest(helpers.ExtendedTestCase):
  """Used to test the Xvfb context manager."""

  def setUp(self):
    helpers.patch(self, ['xvfbwrapper.Xvfb', 'subprocess.Popen', 'time.sleep'])

  def test_correct_oserror_exception(self):
    """Ensures the correct exception is raised when Xvfb is not found."""

    def _raise_with_message(*_unused, **_kwunused):
      del _unused, _kwunused  #Not used by this method
      raise OSError('[Errno 2] No such file or directory')

    self.mock.Popen.side_effect = _raise_with_message
    self.mock.Xvfb.return_value = mock.Mock(
        xvfb_cmd=['not_display', ':display'])

    with self.assertRaises(error.NotInstalledError):
      with reproducers.Xvfb(False) as display_name:
        self.assertNotEqual(display_name, ':display')

    self.assert_n_calls(0, [
        self.mock.Popen.return_value.kill, self.mock.sleep,
        self.mock.Xvfb.return_value.stop
    ])

  def test_incorrect_oserror_exception(self):
    """Ensures OSError raises when message is not Errno 2."""

    self.mock.Popen.side_effect = OSError
    self.mock.Xvfb.return_value = mock.Mock(
        xvfb_cmd=['not_display', ':display'])

    with self.assertRaises(OSError):
      with reproducers.Xvfb(False) as display_name:
        self.assertNotEqual(display_name, ':display')

    self.assert_n_calls(0, [
        self.mock.Popen.return_value.kill, self.mock.sleep,
        self.mock.Xvfb.return_value.stop
    ])

  def test_start_stop_blackbox(self):
    """Tests that the context manager starts/stops xvfbwrapper and blackbox."""

    self.mock.Xvfb.return_value = mock.Mock(
        xvfb_cmd=['not_display', ':display'])

    with reproducers.Xvfb(False) as display_name:
      self.assertEqual(display_name, ':display')

    self.assert_exact_calls(self.mock.Xvfb,
                            [mock.call(width=1280, height=1024)])
    self.assert_exact_calls(self.mock.Xvfb.return_value.start, [mock.call()])
    self.assert_exact_calls(self.mock.Xvfb.return_value.stop,
                            [mock.call.stop()])
    self.assert_exact_calls(
        self.mock.Popen, [mock.call(['blackbox'], env={
            'DISPLAY': ':display'
        })])
    self.assert_exact_calls(self.mock.Popen.return_value.kill, [mock.call()])
    self.assert_exact_calls(self.mock.sleep, [mock.call(3)])

  def test_no_blackbox(self):
    """Tests that the manager doesnt start blackbox when disabled."""

    self.mock.Xvfb.return_value = mock.Mock(
        xvfb_cmd=['not_display', ':display'])

    with reproducers.Xvfb(True) as display_name:
      self.assertEqual(display_name, None)

    self.assert_n_calls(0, [
        self.mock.Xvfb, self.mock.Xvfb.return_value.start,
        self.mock.Xvfb.return_value.stop, self.mock.Popen,
        self.mock.Popen.return_value.kill, self.mock.sleep
    ])


class ReproduceTest(helpers.ExtendedTestCase):
  """Tests the reproduce method within reproducers."""

  def setUp(self):
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)
    helpers.patch(self, [
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.reproduce_debug',
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.reproduce_normal',
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.pre_build_steps',
    ])
    self.mock.reproduce_debug.return_value = True
    self.mock.reproduce_normal.return_value = True

  def test_normal(self):
    """Test reproduce normally."""
    self.reproducer.options = libs.make_options(enable_debug=False)
    self.reproducer.reproduce(10)

    self.mock.pre_build_steps.assert_called_once_with(self.reproducer)
    self.mock.reproduce_normal.assert_called_once_with(self.reproducer, 10)
    self.assertEqual(0, self.mock.reproduce_debug.call_count)

  def test_debug(self):
    """Test reproduce in debugger."""
    self.reproducer.options = libs.make_options(enable_debug=True)
    self.reproducer.reproduce(10)

    self.mock.pre_build_steps.assert_called_once_with(self.reproducer)
    self.mock.reproduce_debug.assert_called_once_with(self.reproducer)
    self.assertEqual(0, self.mock.reproduce_normal.call_count)


class ReproduceNormalTest(helpers.ExtendedTestCase):
  """Tests the reproduce_normal method within reproducers."""

  def setUp(self):
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)
    helpers.patch(self, [
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.reproduce_crash',
        'clusterfuzz.reproducers.symbolize',
        'clusterfuzz.reproducers.get_crash_signature', 'time.sleep'
    ])
    self.mock.reproduce_crash.return_value = (0, 'stuff')
    self.mock.symbolize.return_value = 'stuff'
    self.reproducer.get_crash_signature = lambda: common.CrashSignature(
        'original', ['state'])
    self.reproducer.job_type = 'linux_ubsan_chrome'

  def test_different_stacktrace(self):
    """Tests system exit when the stacktrace doesn't match."""
    self.mock.get_crash_signature.return_value = common.CrashSignature(
        'wrong type', ['incorrect', 'state2'])

    with self.assertRaises(error.DifferentStacktraceError):
      self.reproducer.reproduce_normal(2)

  def test_no_stacktrace(self):
    """Tests system exit when the stacktrace doesn't match."""
    self.mock.get_crash_signature.return_value = common.CrashSignature('', [])

    with self.assertRaises(error.UnreproducibleError):
      self.reproducer.reproduce_normal(2)

  def test_good_stacktrace(self):
    """Tests functionality when the stacktrace matches"""
    self.mock.get_crash_signature.side_effect = [
        common.CrashSignature('wrong type', ['incorrect', 'state2']),
        common.CrashSignature('wrong type', ['incorrect', 'state2']),
        common.CrashSignature('original_type', ['original', 'state'])
    ]

    self.assertTrue(self.reproducer.reproduce_normal(10))
    self.assert_exact_calls(self.mock.reproduce_crash, [
        mock.call(self.reproducer),
        mock.call(self.reproducer),
        mock.call(self.reproducer)
    ])


class ReproduceDebugTest(helpers.ExtendedTestCase):
  """Tests the reproduce_debug method."""

  def setUp(self):
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)
    helpers.patch(self, [
        'clusterfuzz.reproducers.LinuxChromeJobReproducer.reproduce_crash',
    ])

  def test_debug(self):
    """Test running debugger."""
    self.reproducer.reproduce_debug()
    self.mock.reproduce_crash.assert_called_once_with(self.reproducer)


class SymbolizeTest(helpers.ExtendedTestCase):
  """Tests the symbolize method."""

  def setUp(self):
    self.setup_fake_filesystem()
    helpers.patch(self, [
        'clusterfuzz.common.execute',
        'clusterfuzz.common.get_resource',
        'clusterfuzz.common.StringStdin',
    ])
    self.mock.get_resource.return_value = 'asan_sym_proxy.py'
    self.mock.execute.return_value = (0, 'symbolized')

  def test_symbolize_no_output(self):
    """Test to ensure no symbolization is done with no output."""
    result = reproducers.symbolize('', 'source')

    self.assert_exact_calls(self.mock.execute, [])
    self.assertEqual(result, '')

  def test_symbolize_output(self):
    """Test to ensure the correct symbolization call are made."""
    result = reproducers.symbolize('output_lines', '/path/to/chromium')

    self.mock.execute.assert_called_once_with(
        '/path/to/chromium/tools/valgrind/asan/asan_symbolize.py',
        '',
        os.path.expanduser('~'),
        env={
            'LLVM_SYMBOLIZER_PATH': 'asan_sym_proxy.py',
            'CHROMIUM_SRC': '/path/to/chromium'
        },
        stdout_transformer=mock.ANY,
        capture_output=True,
        exit_on_error=True,
        stdin=self.mock.StringStdin.return_value,
        redirect_stderr_to_stdout=True)
    self.assertIsInstance(self.mock.execute.call_args[1]['stdout_transformer'],
                          output_transformer.Identity)
    self.mock.StringStdin.assert_called_once_with('output_lines\0')
    self.assertEqual(result, 'symbolized')


class StripHtmlTest(helpers.ExtendedTestCase):
  """Test strip_html."""

  def test_strip_html(self):
    """Test strip <a> tag."""
    self.assertEqual(['aa test &'],
                     reproducers.strip_html(
                         ['aa <a href="sadfsd">test</a> &amp;']))


class GetOnlyFirstStacktraceTest(helpers.ExtendedTestCase):
  """Test get_only_first_stacktrace."""

  def test_one_trace(self):
    """Test having only one trace."""
    self.assertEqual(['aa', 'bb'],
                     reproducers.get_only_first_stacktrace(['  ', 'aa  ',
                                                            'bb']))

  def test_unsymbolized_stacktrace(self):
    """Test unsymbolized stacktrace."""
    self.assertEqual(
        ['+------- fake trace ----+', 'aa', 'bb'],
        reproducers.get_only_first_stacktrace([
            '   ', '+------- fake trace ----+', 'aa', 'bb',
            '+------Release Build Unsymbolized Stacktrace (diff)------+', 'cc'
        ]))


class LibfuzzerJobReproducerPreBuildStepsTest(helpers.ExtendedTestCase):
  """Test Libfuzzer.pre_build_steps."""

  def test_set_args(self):
    """Test fixing dict."""
    reproducer = create_reproducer(reproducers.LibfuzzerJobReproducer)
    reproducer.args = '-aaa=bbb -dict=/a/b/c/fuzzer.dict -ccc=ddd'
    reproducer.pre_build_steps()

    self.assertEqual('-aaa=bbb -ccc=ddd -dict=/fake/build_dir/fuzzer.dict'
                     ' --test /fake/testcase_dir/testcase', reproducer.args)


class DeserializeLibfuzzerArgsTest(helpers.ExtendedTestCase):
  """Test deserializer_libfuzzer_args."""

  def test_empty(self):
    """Test empty string."""
    self.assertEqual({}, reproducers.deserialize_libfuzzer_args('   '))

  def test_parse(self):
    """Test parsing."""
    self.assertEqual({
        'aaa': 'bbb',
        'ccc': 'ddd',
        'eee': 'fff'
    }, reproducers.deserialize_libfuzzer_args(' -aaa=bbb   -ccc=ddd  -eee=fff'))


class SerializeLibfuzzerArgsTest(helpers.ExtendedTestCase):
  """Test serializer_libfuzzer_args."""

  def test_empty(self):
    """Test empty dict."""
    self.assertEqual('', reproducers.serialize_libfuzzer_args({}))

  def test_serialize(self):
    """Test serializing."""
    self.assertEqual('-aaa=bbb -ccc=ddd -eee=fff',
                     reproducers.serialize_libfuzzer_args({
                         'aaa': 'bbb',
                         'eee': 'fff',
                         'ccc': 'ddd'
                     }))


class MaybeFixDictArgTest(helpers.ExtendedTestCase):
  """Test maybe_fix_dict_args."""

  def test_no_dict_arg(self):
    """Test no dict arg."""
    args = reproducers.maybe_fix_dict_args({'aaa': 'bbb'}, '/fake/path')
    self.assertEqual({'aaa': 'bbb'}, args)

  def test_dict_arg(self):
    """Test fix dict arg."""
    args = reproducers.maybe_fix_dict_args({
        'aaa': 'bbb',
        'dict': '/a/b/c/fuzzer.dict',
        'c': 'd'
    }, '/fake/path')
    self.assertEqual({
        'aaa': 'bbb',
        'dict': '/fake/path/fuzzer.dict',
        'c': 'd'
    }, args)


class IsSimilarTest(helpers.ExtendedTestCase):
  """Test is_similar."""

  def test_not_similar(self):
    """Test not similar."""
    self.assertFalse(
        reproducers.is_similar(
            common.CrashSignature('t', ['a']), common.CrashSignature(
                'z', ['b'])))
    self.assertFalse(
        reproducers.is_similar(
            common.CrashSignature('t', ['a', 'b']),
            common.CrashSignature('t', ['a', 'c', 'd'])))
    self.assertFalse(
        reproducers.is_similar(
            common.CrashSignature('t', ['a']),
            common.CrashSignature('t', ['a', 'c', 'b'])))

  def test_similar(self):
    """Test similar."""
    self.assertTrue(
        reproducers.is_similar(
            common.CrashSignature('t', ['a']), common.CrashSignature(
                'z', ['a'])))
    self.assertTrue(
        reproducers.is_similar(
            common.CrashSignature('t', ['a', 'b']),
            common.CrashSignature('t', ['a', 'c'])))
    self.assertTrue(
        reproducers.is_similar(
            common.CrashSignature('t', ['a']),
            common.CrashSignature('t', ['a', 'c'])))
    self.assertTrue(
        reproducers.is_similar(
            common.CrashSignature('t', ['a', 'b', 'd']),
            common.CrashSignature('t', ['a', 'b', 'c'])))
    self.assertTrue(
        reproducers.is_similar(
            common.CrashSignature('t', ['a', 'b']),
            common.CrashSignature('t', ['a', 'b', 'c'])))


class EnsureUserDataDirIfNeededTest(helpers.ExtendedTestCase):
  """Test ensure_user_data_dir_if_needed."""

  def setUp(self):
    self.setup_fake_filesystem()
    os.makedirs(reproducers.USER_DATA_DIR_PATH)
    self.assertTrue(os.path.exists(reproducers.USER_DATA_DIR_PATH))

  def test_doing_nothing(self):
    """Test doing nothing."""
    self.assertEqual('--something',
                     reproducers.ensure_user_data_dir_if_needed(
                         '--something', False))

  def test_add_because_it_should(self):
    """Test adding arg because it should have."""
    self.assertEqual(
        '--something --user-data-dir=%s' % reproducers.USER_DATA_DIR_PATH,
        reproducers.ensure_user_data_dir_if_needed('--something', True))
    self.assertFalse(os.path.exists(reproducers.USER_DATA_DIR_PATH))

  def test_add_because_of_previous_args(self):
    """Test replacing arg because it exists."""
    self.assertEqual(
        '--something  --user-data-dir=%s' % reproducers.USER_DATA_DIR_PATH,
        reproducers.ensure_user_data_dir_if_needed(
            '--something --user-data-dir=/tmp/random', False))
    self.assertFalse(os.path.exists(reproducers.USER_DATA_DIR_PATH))


class UpdateTestcasePathInLayoutTestTest(helpers.ExtendedTestCase):
  """Test update_testcase_path_in_layout_test."""

  def setUp(self):
    self.setup_fake_filesystem()
    os.makedirs('/testcase_dir')
    self.fs.CreateFile('/testcase_dir/testcase', contents='Some test')
    os.makedirs('/source/third_party/WebKit/LayoutTests/original_dir')

  def test_doing_nothing(self):
    """Test doing nothing."""
    self.assertEqual('/testpath/testcase',
                     reproducers.update_testcase_path_in_layout_test(
                         '/testpath/testcase', '/original/testcase', '/source',
                         100))
    self.assertEqual('/testcase_dir/testcase',
                     reproducers.update_testcase_path_in_layout_test(
                         '/testcase_dir/testcase',
                         '/original/LayoutTests/original_dir/original_file',
                         '/source/',
                         reproducers.LAYOUT_HACK_CUTOFF_DATE_IN_SECONDS + 100))

  def test_update(self):
    """Update the testcase path."""
    new_path = (
        '/source/third_party/WebKit/LayoutTests/original_dir/original_file')
    self.assertEqual(new_path,
                     reproducers.update_testcase_path_in_layout_test(
                         '/testcase_dir/testcase',
                         '/original/LayoutTests/original_dir/original_file',
                         '/source/', 100))
    with open(new_path) as f:
      self.assertEqual('Some test', f.read())


class UpdateForGdbIfNeededTest(helpers.ExtendedTestCase):
  """Tests update_for_gdb_if_needed."""

  def test_no_update(self):
    """Test no update."""
    self.assertEqual(('b', 'a', 30),
                     reproducers.update_for_gdb_if_needed('b', 'a', 30, False))

  def test_update(self):
    """Test update."""
    self.assertEqual(
        ('gdb', "-ex 'b __sanitizer::Die' -ex run --args b a", None),
        reproducers.update_for_gdb_if_needed('b', 'a', 30, True))


class BaseReproducerGetCrashSignatureTest(helpers.ExtendedTestCase):
  """Test BaseReproducer.get_crash_signature."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.reproducers.get_crash_signature',
    ])

  def test_get(self):
    """Test getting crash signature."""
    self.mock.get_crash_signature.return_value = common.CrashSignature('t', [])
    self.reproducer = create_reproducer(reproducers.LinuxChromeJobReproducer)
    self.assertEqual(self.mock.get_crash_signature.return_value,
                     self.reproducer.get_crash_signature())

    self.mock.get_crash_signature.assert_called_once_with(
        self.reproducer.testcase.job_type, 'line')


class BaseReproducerGetTestcaseUrlTest(helpers.ExtendedTestCase):
  """Test BaseReproducer.get_testcase_url."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.reproducers.BaseReproducer.get_testcase_path',
    ])

  def test_get(self):
    """Tests getting testcase URL."""
    self.mock.get_testcase_path.return_value = '/sdcard/testcase.html'
    self.reproducer = create_reproducer(reproducers.BaseReproducer)
    self.assertEqual('file:///sdcard/testcase.html',
                     self.reproducer.get_testcase_url())

    self.mock.get_testcase_path.assert_called_once_with(self.reproducer)


class GetCrashSignatureTest(helpers.ExtendedTestCase):
  """Test get_crash_signature."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.common.post'])

  def test_get(self):
    """Test get."""
    self.mock.post.return_value = mock.Mock(
        text=json.dumps({
            'crash_state': 'original\nstate',
            'crash_type': 'original_type'
        }))
    self.assertEqual(
        common.CrashSignature('original_type', ['original', 'state']),
        reproducers.get_crash_signature('job', 'raw_stacktrace'))
    self.mock.post.assert_called_once_with(
        url='https://clusterfuzz.com/v2/parse_stacktrace',
        data=json.dumps({
            'job': 'job',
            'stacktrace': 'raw_stacktrace'
        }))


class AndroidChromeReproducerTest(helpers.ExtendedTestCase):
  """Tests methods in AndroidChromeReproducer."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb', 'clusterfuzz.android.adb_shell',
        'clusterfuzz.reproducers.set_device_id_if_possible'
    ])
    self.reproducer = create_reproducer(reproducers.AndroidChromeReproducer)
    self.mock_os_environment({})
    self.reproducer.testcase.id = '1234'
    self.reproducer.testcase.testcase_dir_path = '/something'
    self.reproducer.testcase.get_testcase_path.return_value = (
        '/something/mnt/test.html')

  def test_reproduce_debug(self):
    """Tests AndroidChromeReproducer.reproduce_debug."""
    with self.assertRaises(error.GdbNotSupportedOnAndroidError):
      self.reproducer.reproduce_debug()

  def test_get_device_id(self):
    """Tests AndroidChromeReproducer.get_device_id."""
    os.environ['ANDROID_SERIAL'] = 'test'
    self.assertEqual('test', self.reproducer.get_device_id())
    self.mock.set_device_id_if_possible.assert_called_once_with()

  def test_get_device_id_error(self):
    """Tests AndroidChromeReproducer.get_device_id when erroring."""
    os.environ['ANDROID_SERIAL'] = ''
    with self.assertRaises(error.NoAndroidDeviceIdError):
      self.reproducer.get_device_id()
    self.mock.set_device_id_if_possible.assert_called_once_with()

  def test_get_testcase_path(self):
    """Tests AndroidChromeReproducer.get_testcase_path."""
    self.assertEqual('%s/1234/mnt/test.html' % reproducers.ANDROID_TESTCASE_DIR,
                     self.reproducer.get_testcase_path())
    self.mock.adb.assert_called_once_with(
        'push /something %s/1234' % reproducers.ANDROID_TESTCASE_DIR)
    self.mock.adb_shell.assert_called_once_with(
        'rm -rf %s' % reproducers.ANDROID_TESTCASE_DIR)


class AndroidChromeReproducerPreBuildStepsTest(helpers.ExtendedTestCase):
  """Tests AndroidChromeReproducer.pre_build_steps."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb',
        'clusterfuzz.android.ensure_active',
        'clusterfuzz.android.ensure_asan',
        'clusterfuzz.android.ensure_root_and_remount',
        'clusterfuzz.android.install',
        'clusterfuzz.android.uninstall',
        'clusterfuzz.android.write_content',
        'clusterfuzz.reproducers.AndroidChromeReproducer.get_device_id',
        'clusterfuzz.reproducers.AndroidChromeReproducer.get_testcase_path',
        'clusterfuzz.reproducers.BaseReproducer.pre_build_steps',
    ])
    self.reproducer = create_reproducer(reproducers.AndroidChromeReproducer)
    self.reproducer.testcase.files = {'test-file': 'content'}
    self.reproducer.testcase.command_line_file_path = (
        '/data/local/tmp/chrome-command-line')
    self.mock.get_device_id.return_value = 'device'

  def test_pre_build_steps(self):
    """Tests AndroidChromeReproducer.pre_build_steps."""
    self.reproducer.pre_build_steps()

    self.mock.ensure_root_and_remount.assert_called_once_with()
    self.mock.ensure_active.assert_called_once_with()
    self.mock.ensure_asan(
        android_libclang_dir_path=(
            self.reproducer.binary_provider.get_android_libclang_dir_path()),
        device_id='device')
    self.mock.uninstall.assert_called_once_with(
        self.reproducer.testcase.android_package_name)
    self.mock.install.assert_called_once_with(self.reproducer.binary_path)
    self.assert_exact_calls(self.mock.write_content, [
        mock.call('test-file', 'content'),
        mock.call('/data/local/tmp/chrome-command-line',
                  'chrome %s' % self.reproducer.args)
    ])


class AndroidChromeReproducerReproduceCrashTest(helpers.ExtendedTestCase):
  """Tests AndroidChromeReproducer.reproduce_crash."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb_shell',
        'clusterfuzz.android.clear_log',
        'clusterfuzz.android.ensure_active',
        'clusterfuzz.android.filter_log',
        'clusterfuzz.android.fix_lib_path',
        'clusterfuzz.android.get_log',
        'clusterfuzz.android.kill',
        'clusterfuzz.android.reboot',
        'clusterfuzz.android.reset',
        'clusterfuzz.reproducers.AndroidChromeReproducer.get_testcase_url',
        'clusterfuzz.reproducers.symbolize',
        'clusterfuzz.reproducers.run_monkey_gestures_if_needed',
        'time.sleep',
    ])
    self.reproducer = create_reproducer(reproducers.AndroidChromeReproducer)
    self.reproducer.testcase.android_package_name = 'android.package'
    self.reproducer.testcase.android_main_class_name = 'android.Main'
    self.reproducer.testcase.gestures = ['monkey,1234']
    self.mock.get_testcase_url.return_value = 'testcase-path'
    self.setup_fake_filesystem()
    os.makedirs(common.CLUSTERFUZZ_TMP_DIR)

  def test_reproduce_crash(self):
    """Tests AndroidChromeReproducer.reproduce_crash."""
    self.mock.adb_shell.return_value = (0, 'dontcare')
    self.mock.get_log.return_value = 'raw log'
    self.mock.filter_log.return_value = 'filtered log'
    self.mock.fix_lib_path.return_value = 'fixed log'
    self.mock.symbolize.return_value = 'symbolized'

    self.assertEqual((0, 'symbolized'), self.reproducer.reproduce_crash())

    self.mock.reset.assert_called_once_with('android.package')
    self.mock.reboot.assert_called_once_with()
    self.mock.ensure_active.assert_called_once_with()
    self.mock.clear_log.assert_called_once_with()
    self.mock.adb_shell.assert_called_once_with(
        ('am start -a android.intent.action.MAIN -n '
         "android.package/android.Main 'testcase-path'"),
        redirect_stderr_to_stdout=True,
        stdout_transformer=mock.ANY)
    self.mock.sleep.assert_called_once_with(30)
    self.mock.get_log.assert_called_once_with()
    self.mock.kill.assert_called_once_with('android.package')
    self.mock.filter_log.assert_called_once_with('raw log')
    self.mock.fix_lib_path.assert_called_once_with(
        content='filtered log',
        search_paths=[
            self.reproducer.binary_provider.get_unstripped_lib_dir_path(),
            self.reproducer.binary_provider.get_android_libclang_dir_path(),
        ],
        lib_tmp_dir_path=mock.ANY)
    self.mock.symbolize.assert_called_once_with(
        'fixed log', self.reproducer.binary_provider.get_source_dir_path())
    self.mock.run_monkey_gestures_if_needed.assert_called_once_with(
        self.reproducer.testcase.android_package_name,
        self.reproducer.testcase.gestures)


class AndroidWebViewReproducerTest(helpers.ExtendedTestCase):
  """Tests AndroidWebViewReproducer.install."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.android.adb', 'clusterfuzz.android.adb_shell',
        'clusterfuzz.android.install', 'clusterfuzz.android.uninstall'
    ])

  def test_install(self):
    """Tests installing webview."""
    self.reproducer = create_reproducer(reproducers.AndroidWebViewReproducer)
    self.reproducer.install()

    self.assert_exact_calls(self.mock.adb_shell, [
        mock.call('setprop persist.sys.webview.vmsize %s' %
                  reproducers.SYSTEM_WEBVIEW_VMSIZE_BYTES),
        mock.call('stop'),
        mock.call('rm -rf %s' % ' '.join(reproducers.SYSTEM_WEBVIEW_DIRS)),
        mock.call('start')
    ])
    self.assert_exact_calls(self.mock.uninstall, [
        mock.call(reproducers.SYSTEM_WEBVIEW_PACKAGE),
        mock.call(self.reproducer.testcase.android_package_name)
    ])
    self.assert_exact_calls(self.mock.install, [
        mock.call(
            os.path.join(
                os.path.dirname(self.reproducer.binary_path),
                reproducers.SYSTEM_WEBVIEW_APK)),
        mock.call(self.reproducer.binary_path)
    ])


class SetDeviceIdIfPossibleTest(helpers.ExtendedTestCase):
  """Tests set_device_id_if_possible."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.adb'])
    self.mock_os_environment({})

  def test_get(self):
    """Tests getting device id."""
    self.mock.adb.return_value = (0, ('List of devices attached\n'
                                      '06c02c4b003b806f       device\n'))
    reproducers.set_device_id_if_possible()
    self.assertEqual('06c02c4b003b806f',
                     os.environ.get(reproducers.ANDROID_SERIAL_ENV))
    self.mock.adb.assert_called_once_with('devices')

  def test_multiple(self):
    """Tests not getting device id because there are multiple devices."""
    self.mock.adb.return_value = (0, ('List of devices attached\n'
                                      '06c02c4b003b806f       device\n'
                                      'ZX1SDGWE       device\n'))
    reproducers.set_device_id_if_possible()
    self.assertIsNone(os.environ.get(reproducers.ANDROID_SERIAL_ENV))
    self.mock.adb.assert_called_once_with('devices')

  def test_no_device(self):
    """Tests no devices."""
    self.mock.adb.return_value = (0, 'List of devices attached\n')
    reproducers.set_device_id_if_possible()
    self.assertIsNone(os.environ.get(reproducers.ANDROID_SERIAL_ENV))
    self.mock.adb.assert_called_once_with('devices')

  def test_env_set(self):
    """Tests env is already set."""
    os.environ[reproducers.ANDROID_SERIAL_ENV] = 'device'
    reproducers.set_device_id_if_possible()
    self.assertEqual('device', os.environ.get(reproducers.ANDROID_SERIAL_ENV))
    self.assertEqual(0, self.mock.adb.call_count)


class RunMonkeyGesturesIfNeededTest(helpers.ExtendedTestCase):
  """Tests run_monkey_gestures_if_needed."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.android.adb_shell', 'time.sleep'])

  def test_no_gestures(self):
    """Tests no gestures."""
    reproducers.run_monkey_gestures_if_needed('package', None)
    reproducers.run_monkey_gestures_if_needed('package', [])
    self.assertEqual(0, self.mock.adb_shell.call_count)

  def test_not_monkey(self):
    """Tests not monkey."""
    reproducers.run_monkey_gestures_if_needed('package', ['something,else'])
    self.assertEqual(0, self.mock.adb_shell.call_count)

  def test_run(self):
    """Tests run."""
    reproducers.run_monkey_gestures_if_needed('package', ['monkey,123'])
    self.mock.adb_shell.assert_called_once_with(
        'monkey -p package -s 123 --throttle %s '
        '--ignore-security-exceptions %s' % (reproducers.MONKEY_THROTTLE_DELAY,
                                             reproducers.NUM_MONKEY_EVENTS))
