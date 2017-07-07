"""Sends the results of CI testing to stackdriver."""

import json
import os

from httplib2 import Http
from oauth2client.client import GoogleCredentials
from error import error


def send_log(params, success):
  """Send a log to Stackdriver with the result of a testcase run."""
  credentials = GoogleCredentials.get_application_default()
  http_auth = credentials.authorize(Http())

  structure = {
      'logName': 'projects/%s/logs/ci' % os.environ['PROJECT_ID'],
      'resource': {
          'type': 'project',
          'labels': {
              'project_id': os.environ['PROJECT_ID']}},
      'entries': [{
          'jsonPayload': params,
          'severity': 'INFO' if success else 'ERROR'}]}

  http_auth.request(
      uri='https://logging.googleapis.com/v2/entries:write',
      method='POST',
      body=json.dumps(structure))


def send_run(
    testcase_id, testcase_type, version, release, return_code, logs, opts):
  """Send log to Stackdriver."""
  error_name = ''
  success = return_code == 0
  opts_str = ''

  if opts:
    opts_str = ', %s' % opts

  if success:
    message = '%s (%s) reproduced %s successfully (%s%s).' % (
        version, release, testcase_id, testcase_type, opts_str)
  else:
    error_name = error.get_class_name(return_code)
    message = (
        '%s (%s) failed to reproduce %s (%s, %s%s).' %
        (version, release, testcase_id, testcase_type, error_name, opts_str))

  send_log(
      params={
          'testcaseId': testcase_id,
          'type': testcase_type, # Sanity check or pulled testcase
          'version': version,
          'message': message,
          'release': release,
          'returnCode': return_code,
          'error': error_name,
          # Only write logs when failing to save space.
          'logs': '' if success else logs,
          'opts': opts
      },
      success=success)
