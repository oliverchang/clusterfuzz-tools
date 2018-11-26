"""Helper methods to make tests shorter."""
# TODO(tanin): rename this module to helpers once we rename shared/helpers.

from __future__ import absolute_import

from clusterfuzz import binary_providers
from clusterfuzz import reproducers
from clusterfuzz import common
from clusterfuzz import testcase


def make_testcase(
    testcase_id='1',
    stacktrace_lines='a\nb\nc\n',
    environment=None,
    reproduction_args='--args',
    revision=12345,
    build_url='build_url',
    job_type='job_type',
    absolute_path='absolute_path.html',
    reproducible=True,
    gestures='gestures',
    crash_type='type',
    crash_state='state1\nstate2',
    raw_gn_args='a=b\nc=d',
    files=None,
    command_line_file_path=None,
    android_package_name=None,
    android_main_class_name=None,
    created_at=100,
    platform='linux'):
  """Make a testcase."""
  if files is None:
    files = {'test.conf': 'test-conf-content'}
  return testcase.Testcase(
      testcase_id=testcase_id,
      stacktrace_lines=stacktrace_lines,
      environment=(environment or {}),
      reproduction_args=reproduction_args,
      revision=revision,
      build_url=build_url,
      job_type=job_type,
      absolute_path=absolute_path,
      reproducible=reproducible,
      gestures=gestures,
      crash_type=crash_type,
      crash_state=crash_state,
      raw_gn_args=raw_gn_args,
      files=files,
      command_line_file_path=command_line_file_path,
      android_package_name=android_package_name,
      android_main_class_name=android_main_class_name,
      created_at=created_at,
      platform=platform)


def make_definition(
    builder=binary_providers.ChromiumBuilder,
    source_name='chromium',
    reproducer=reproducers.LinuxChromeJobReproducer,
    binary_name='chrome',
    sanitizer='ASAN',
    targets=None,
    require_user_data_dir=True,
    revision_url=None):
  """Make a definition."""
  if targets is None:
    targets = ['chromium_builder_asan']
  return common.Definition(
      builder=builder,
      source_name=source_name,
      reproducer=reproducer,
      binary_name=binary_name,
      sanitizer=sanitizer,
      targets=targets,
      require_user_data_dir=require_user_data_dir,
      revision_url=revision_url)


def make_options(
    testcase_id='1',
    current=False,
    build='chromium',
    disable_goma=False,
    goma_threads=10,
    goma_load=8,
    iterations=11,
    disable_xvfb=False,
    target_args=None,
    edit_mode=False,
    skip_deps=False,
    enable_debug=False,
    extra_log_params=None,
    force=False):
  """Make an option."""
  extra_log_params = extra_log_params or {}
  return common.Options(
      testcase_id=testcase_id,
      current=current,
      build=build,
      disable_goma=disable_goma,
      goma_threads=goma_threads,
      goma_load=goma_load,
      iterations=iterations,
      disable_xvfb=disable_xvfb,
      target_args=target_args,
      edit_mode=edit_mode,
      skip_deps=skip_deps,
      enable_debug=enable_debug,
      extra_log_params=extra_log_params,
      force=force)
