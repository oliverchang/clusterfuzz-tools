"""Test the module for the 'reproduce' command"""
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

import json
import os
import mock

from clusterfuzz import common
from clusterfuzz import binary_providers
from clusterfuzz import reproducers
from clusterfuzz.commands import reproduce
from error import error
from tests import libs
from test_libs import helpers


class WarnUnreproducibleIfNeeded(helpers.ExtendedTestCase):
  """Test warn_unreproducible_if_needed."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.commands.reproduce.logger.info'])

  def test_warn(self):
    """Test warn."""
    reproduce.warn_unreproducible_if_needed(
        mock.Mock(reproducible=False, gestures='gestures'))

    self.assertEqual(2, self.mock.info.call_count)

  def test_not_warn(self):
    """Test warn."""
    reproduce.warn_unreproducible_if_needed(
        mock.Mock(reproducible=True, gestures=None))
    self.assertEqual(0, self.mock.info.call_count)


class ExecuteTest(helpers.ExtendedTestCase):
  """Test execute."""

  def setUp(self):
    self.suppress_logging_methods()
    self.chrome_src = '/usr/local/google/home/user/repos/chromium/src'
    self.mock_os_environment({'V8_SRC': '/v8/src', 'CHROME_SRC': '/pdf/src'})
    helpers.patch(self, [
        'clusterfuzz.binary_providers.DownloadedBinary',
        'clusterfuzz.binary_providers.V8Builder',
        'clusterfuzz.binary_providers.ChromiumBuilder',
        'clusterfuzz.commands.reproduce.get_definition',
        'clusterfuzz.commands.reproduce.get_testcase',
        'clusterfuzz.commands.reproduce.ensure_goma',
        'clusterfuzz.testcase.Testcase.get_testcase_path',
    ])
    self.mock.ensure_goma.return_value = '/goma/dir'

    self.builder = mock.Mock(symbolizer_path='/path/to/symbolizer')
    self.reproducer = mock.Mock()
    self.definition = mock.Mock()

    self.definition.builder.return_value = self.builder
    self.definition.reproducer.return_value = self.reproducer

    self.mock.get_definition.return_value = self.definition
    self.mock.DownloadedBinary.return_value = self.builder

    self.testcase = mock.Mock(
        id='1234', build_url='chrome_build_url', revision=123456,
        job_type='linux_asan_d8', reproducible=True,
        reproduction_args='--always-opt')
    self.mock.get_testcase.return_value = self.testcase
    self.options = libs.make_options(testcase_id=str(self.testcase.id))

  def test_download_no_defined_binary(self):
    """Test what happens when no binary name is defined."""
    self.definition.binary_name = None
    self.testcase.stacktrace_lines = [
        {'content': 'incorrect'}, {'content': '[Environment] A = b'},
        {'content': ('Running command: path/to/stacktrace_binary --args --arg2 '
                     '/path/to/testcase')}]

    self.options.build = 'download'
    reproduce.execute(**vars(self.options))

    self.mock.get_testcase.assert_called_once_with(self.testcase.id)
    self.assert_n_calls(0, [self.mock.ensure_goma])
    self.mock.DownloadedBinary.assert_called_once_with(
        self.testcase.id, self.testcase.build_url, 'stacktrace_binary')
    self.definition.reproducer.assert_called_once_with(
        binary_provider=self.mock.DownloadedBinary.return_value,
        definition=self.definition,
        testcase=self.testcase,
        sanitizer=self.definition.sanitizer,
        options=self.options)
    self.assertEqual(0, self.builder.build.call_count)

  def test_grab_data_with_download(self):
    """Ensures all method calls are made correctly when downloading."""
    self.definition.binary_name = 'defined_binary'
    self.testcase.stacktrace_lines = [
        {'content': 'incorrect'}, {'content': '[Environment] A = b'},
        {'content': ('Running command: path/to/stacktrace_binary --args --arg2 '
                     '/path/to/testcase')}]

    self.options.build = 'download'
    reproduce.execute(**vars(self.options))

    self.mock.get_testcase.assert_called_once_with(self.testcase.id)
    self.assert_n_calls(0, [self.mock.ensure_goma])
    self.mock.DownloadedBinary.assert_called_once_with(
        self.testcase.id, self.testcase.build_url, 'defined_binary')
    self.definition.reproducer.assert_called_once_with(
        binary_provider=self.mock.DownloadedBinary.return_value,
        definition=self.definition,
        testcase=self.testcase,
        sanitizer=self.definition.sanitizer,
        options=self.options)
    self.assertEqual(0, self.builder.build.call_count)

  def test_grab_data_standalone(self):
    """Ensures all method calls are made correctly when building locally."""
    self.options.build = 'standalone'
    reproduce.execute(**vars(self.options))
    self.options.goma_dir = '/goma/dir'

    self.mock.get_testcase.assert_called_once_with(self.testcase.id)
    self.mock.ensure_goma.assert_called_once_with()
    self.definition.builder.assert_called_once_with(
        testcase=self.testcase,
        definition=self.definition,
        options=self.options)
    self.definition.reproducer.assert_called_once_with(
        binary_provider=self.builder,
        definition=self.definition,
        testcase=self.testcase,
        sanitizer=self.definition.sanitizer,
        options=self.options)
    self.builder.build.assert_called_once_with()


class SendRequestTest(helpers.ExtendedTestCase):
  """Test send_request."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.common.get_stored_auth_header',
        'clusterfuzz.common.store_auth_header',
        'clusterfuzz.commands.reproduce.get_verification_header',
        'clusterfuzz.common.post'])

  def test_correct_stored_authorization(self):
    """Ensures that the testcase info is returned when stored auth is correct"""

    response_headers = {'x-clusterfuzz-authorization': 'Bearer 12345'}
    response_dict = {
        'id': '12345',
        'crash_type': 'Bad Crash',
        'crash_state': ['Halted']}

    self.mock.get_stored_auth_header.return_value = 'Bearer 12345'
    self.mock.post.return_value = mock.Mock(
        status_code=200,
        text=json.dumps(response_dict),
        headers=response_headers)

    response = reproduce.send_request('url', 'data')

    self.assert_exact_calls(self.mock.get_stored_auth_header, [mock.call()])
    self.assert_exact_calls(
        self.mock.store_auth_header, [mock.call('Bearer 12345')])
    self.assert_exact_calls(self.mock.post, [mock.call(
        url='url',
        headers={'Authorization': 'Bearer 12345',
                 'User-Agent': 'clusterfuzz-tools'},
        data='data',
        allow_redirects=True)])
    self.assertEqual(200, response.status_code)

  def test_incorrect_stored_header(self):
    """Tests when the header is stored, but has expired/is invalid."""

    response_headers = {'x-clusterfuzz-authorization': 'Bearer 12345'}
    response_dict = {
        'id': '12345',
        'crash_type': 'Bad Crash',
        'crash_state': ['Halted']}

    self.mock.post.side_effect = [
        mock.Mock(status_code=401),
        mock.Mock(status_code=200,
                  text=json.dumps(response_dict),
                  headers=response_headers)]
    self.mock.get_stored_auth_header.return_value = 'Bearer 12345'
    self.mock.get_verification_header.return_value = 'VerificationCode 12345'

    response = reproduce.send_request('url', 'data')

    self.assert_exact_calls(self.mock.get_stored_auth_header, [mock.call()])
    self.assert_exact_calls(self.mock.get_verification_header, [mock.call()])
    self.assert_exact_calls(self.mock.post, [
        mock.call(
            allow_redirects=True,
            url='url',
            data='data',
            headers={'Authorization': 'Bearer 12345',
                     'User-Agent': 'clusterfuzz-tools'}),
        mock.call(
            headers={'Authorization': 'VerificationCode 12345',
                     'User-Agent': 'clusterfuzz-tools'},
            allow_redirects=True,
            data='data',
            url='url')])
    self.assert_exact_calls(self.mock.store_auth_header, [
        mock.call('Bearer 12345')])
    self.assertEqual(200, response.status_code)


  def test_correct_verification_auth(self):
    """Tests grabbing testcase info when the local header is invalid."""

    response_headers = {'x-clusterfuzz-authorization': 'Bearer 12345'}
    response_dict = {
        'id': '12345',
        'crash_type': 'Bad Crash',
        'crash_state': ['Halted']}

    self.mock.get_stored_auth_header.return_value = None
    self.mock.get_verification_header.return_value = 'VerificationCode 12345'
    self.mock.post.return_value = mock.Mock(
        status_code=200,
        text=json.dumps(response_dict),
        headers=response_headers)

    response = reproduce.send_request('url', 'data')

    self.assert_exact_calls(self.mock.get_stored_auth_header, [mock.call()])
    self.assert_exact_calls(self.mock.get_verification_header, [mock.call()])
    self.assert_exact_calls(self.mock.store_auth_header, [
        mock.call('Bearer 12345')])
    self.assert_exact_calls(self.mock.post, [mock.call(
        headers={'Authorization': 'VerificationCode 12345',
                 'User-Agent': 'clusterfuzz-tools'},
        allow_redirects=True,
        data='data',
        url='url')])
    self.assertEqual(200, response.status_code)

  def test_incorrect_authorization(self):
    """Ensures that when auth is incorrect the right exception is thrown"""

    response_headers = {'x-clusterfuzz-authorization': 'Bearer 12345'}
    response_dict = {
        'status': 401,
        'type': 'UnauthorizedException',
        'message': {
            'Invalid verification code (12345)': {
                'error': 'invalid_grant',
                'error_description': 'Bad Request'}},
        'params': {
            'testcaseId': ['999']},
        'email': 'test@email.com'}

    self.mock.get_stored_auth_header.return_value = 'Bearer 12345'
    self.mock.get_verification_header.return_value = 'VerificationCode 12345'
    self.mock.post.return_value = mock.Mock(
        status_code=401,
        text=json.dumps(response_dict),
        headers=response_headers)

    with self.assertRaises(error.ClusterFuzzError) as cm:
      reproduce.send_request('url', 'data')

    self.assertEqual(401, cm.exception.status_code)
    self.assert_exact_calls(self.mock.post, [
        mock.call(
            allow_redirects=True,
            url='url',
            data='data',
            headers={'Authorization': 'Bearer 12345',
                     'User-Agent': 'clusterfuzz-tools'}),
        mock.call(
            allow_redirects=True,
            headers={'Authorization': 'VerificationCode 12345',
                     'User-Agent': 'clusterfuzz-tools'},
            url='url',
            data='data')])


class GetTestcaseTest(helpers.ExtendedTestCase):
  """Test get_testcase."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz.commands.reproduce.send_request',
        'clusterfuzz.testcase.create'
    ])

  def test_succeed(self):
    """Test succeed."""
    self.mock.send_request.return_value = mock.Mock(text='{"test": "ok"}')
    self.mock.create.return_value = 'dummy testcase'
    self.assertEqual('dummy testcase', reproduce.get_testcase('12345'))

    self.mock.send_request.assert_called_once_with(
        reproduce.CLUSTERFUZZ_TESTCASE_INFO_URL, '{"testcaseId": "12345"}')

  def test_404(self):
    """Test 404."""
    self.mock.send_request.side_effect = error.ClusterFuzzError(404, 'resp')
    with self.assertRaises(error.InvalidTestcaseIdError) as cm:
      reproduce.get_testcase('12345')

    self.assertIn('12345', cm.exception.message)
    self.mock.send_request.assert_called_once_with(
        reproduce.CLUSTERFUZZ_TESTCASE_INFO_URL, '{"testcaseId": "12345"}')

  def test_401(self):
    """Test 401."""
    self.mock.send_request.side_effect = error.ClusterFuzzError(401, 'resp')
    with self.assertRaises(error.UnauthorizedError) as cm:
      reproduce.get_testcase('12345')

    self.assertIn('12345', cm.exception.message)
    self.mock.send_request.assert_called_once_with(
        reproduce.CLUSTERFUZZ_TESTCASE_INFO_URL, '{"testcaseId": "12345"}')

  def test_error(self):
    """Test other error."""
    self.mock.send_request.side_effect = error.ClusterFuzzError(500, 'resp')
    with self.assertRaises(error.ClusterFuzzError) as cm:
      reproduce.get_testcase('12345')

    self.assertEqual(500, cm.exception.status_code)
    self.assertIn('resp', cm.exception.message)
    self.mock.send_request.assert_called_once_with(
        reproduce.CLUSTERFUZZ_TESTCASE_INFO_URL, '{"testcaseId": "12345"}')


class GetVerificationHeaderTest(helpers.ExtendedTestCase):
  """Tests the get_verification_header method"""

  def setUp(self):
    helpers.patch(self, [
        'webbrowser.open',
        'clusterfuzz.common.ask'])
    self.mock.ask.return_value = '12345'

  def test_returns_correct_header(self):
    """Tests that the correct token with header is returned."""

    response = reproduce.get_verification_header()

    self.mock.open.assert_has_calls([mock.call(
        reproduce.GOOGLE_OAUTH_URL,
        new=1,
        autoraise=True)])
    self.assertEqual(response, 'VerificationCode 12345')


class EnsureGomaTest(helpers.ExtendedTestCase):
  """Tests the ensure_goma method."""

  def setUp(self):
    self.setup_fake_filesystem()
    self.mock_os_environment(
        {'GOMA_DIR': os.path.expanduser(os.path.join('~', 'goma'))})
    helpers.patch(self, ['clusterfuzz.common.execute'])

  def test_goma_not_installed(self):
    """Tests what happens when GOMA is not installed."""

    with self.assertRaises(error.GomaNotInstalledError) as ex:
      reproduce.ensure_goma()
      self.assertTrue('goma is not installed' in ex.message)

  def test_goma_installed(self):
    """Tests what happens when GOMA is installed."""

    goma_dir = os.path.expanduser(os.path.join('~', 'goma'))
    os.makedirs(goma_dir)
    f = open(os.path.join(goma_dir, 'goma_ctl.py'), 'w')
    f.close()

    result = reproduce.ensure_goma()

    self.assert_exact_calls(self.mock.execute, [
        mock.call('python', 'goma_ctl.py ensure_start', goma_dir)
    ])
    self.assertEqual(result, goma_dir)


class SuppressOutputTest(helpers.ExtendedTestCase):
  """Test SuppressOutput."""

  def setUp(self):
    helpers.patch(self, ['os.dup', 'os.open', 'os.close', 'os.dup2'])

    def dup(number):
      if number == 1:
        return 'out'
      elif number == 2:
        return 'err'
    self.mock.dup.side_effect = dup

  def test_suppress(self):
    """Test suppressing output."""
    with reproduce.SuppressOutput():
      pass

    self.assert_exact_calls(self.mock.dup, [mock.call(1), mock.call(2)])
    self.assert_exact_calls(self.mock.close, [mock.call(1), mock.call(2)])
    self.mock.open.assert_called_once_with(os.devnull, os.O_RDWR)
    self.assert_exact_calls(
        self.mock.dup2, [mock.call('out', 1), mock.call('err', 2)])

  def test_exception(self):
    """Test absorbing exception."""
    with reproduce.SuppressOutput():
      raise Exception('test_exc')

    self.assert_exact_calls(self.mock.dup, [mock.call(1), mock.call(2)])
    self.assert_exact_calls(self.mock.close, [mock.call(1), mock.call(2)])
    self.mock.open.assert_called_once_with(os.devnull, os.O_RDWR)
    self.assert_exact_calls(
        self.mock.dup2, [mock.call('out', 1), mock.call('err', 2)])


class GetDefinitionTest(helpers.ExtendedTestCase):
  """Tests getting binary definitions."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz.commands.reproduce.get_supported_jobs'])
    self.mock.get_supported_jobs.return_value = {
        'chromium': {
            'libfuzzer_chrome_msan': common.Definition(
                builder=binary_providers.ChromiumBuilder,
                source_var='CHROMIUM_SRC',
                reproducer=reproducers.BaseReproducer,
                binary_name=None,
                sanitizer='MSAN',
                target=None,
                require_user_data_dir=False)},
        'standalone': {}}

  def test_download_param(self):
    """Tests when the build_param is download"""

    result = reproduce.get_definition('libfuzzer_chrome_msan', 'download')
    self.assertEqual(result.builder, binary_providers.ChromiumBuilder)

    with self.assertRaises(error.JobTypeNotSupportedError):
      result = reproduce.get_definition('fuzzlibber_nasm', 'download')

  def test_build_param(self):
    """Tests when build_param is an option that requires building."""

    result = reproduce.get_definition('libfuzzer_chrome_msan', 'chromium')
    self.assertEqual(result.builder, binary_providers.ChromiumBuilder)

    with self.assertRaises(error.JobTypeNotSupportedError):
      result = reproduce.get_definition('fuzzlibber_nasm', 'chromium')


class GetSupportedJobsTest(helpers.ExtendedTestCase):
  """Tests the get_supported_jobs method."""

  def test_raise_from_key_error(self):
    """Tests that a BadJobTypeDefinition error is raised when parsing fails."""
    helpers.patch(self, [
        'clusterfuzz.commands.reproduce.build_definition'])
    self.mock.build_definition.side_effect = KeyError

    with self.assertRaises(error.BadJobTypeDefinitionError):
      reproduce.get_supported_jobs()

  def test_get(self):
    """Test getting supported job types."""
    results = reproduce.get_supported_jobs()
    self.assertIn('chromium', results)
    self.assertIn('libfuzzer_chrome_ubsan', results['chromium'])
    self.assertIn('standalone', results)
    self.assertIn('linux_asan_pdfium', results['standalone'])
