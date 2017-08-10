"""The module handles running a command line."""

import os
import signal
import subprocess
import threading
import time


LAST_PID_FILE = '/python-daemon-data/last_pid'
DEFAULT_TIMEOUT = 30 * 60  # 30 minutes.


def call(cmd, cwd='.', env=None, capture=False, raise_on_error=True,
         timeout=DEFAULT_TIMEOUT):
  """Call invoke command with additional envs and return output."""
  env = env or {}
  env_str = ' '.join(
      ['%s="%s"' % (k, v) for k, v in env.iteritems()])
  print ('Running:\n  cmd: %s %s\n  cwd: %s' % (env_str, cmd, cwd)).strip()

  final_env = os.environ.copy()
  final_env.update(env)

  with Popen(
      cmd, shell=True, cwd=cwd, env=final_env, preexec_fn=os.setsid,
      stdout=subprocess.PIPE if capture else None) as proc:
    threading.Thread(target=kill_when_timeout, args=(proc, timeout)).start()
    out, _ = proc.communicate()

    if proc.returncode != 0 and raise_on_error:
      raise subprocess.CalledProcessError(
          returncode=proc.returncode, cmd=cmd, output=out)

    return proc.returncode, out


def kill_when_timeout(popen, timeout):
  """Kill when the timeout is reached."""
  start_time = time.time()

  while popen.poll() is None and (time.time() - start_time) < timeout:
    time.sleep(1)

  if popen.poll() is None:
    try:
      popen.kill()
    except OSError:
      pass


class Popen(object):
  """A scope that initializes Popen and kill the last pid."""

  def __init__(self, *args, **kwargs):
    kill_last_pid()
    self.popen = subprocess.Popen(*args, **kwargs)
    store_last_pid(self.popen.pid)

  def __enter__(self):
    return self.popen

  def __exit__(self, exc_type, exc_val, exc_tb):
    kill_last_pid()


def store_last_pid(pid):
  """Store the last pid, so that we can kill it later in time."""
  with open(LAST_PID_FILE, 'w') as f:
    f.write('%s' % pid)


def kill_last_pid():
  """Kill the last pid. See:
    https://github.com/google/clusterfuzz-tools/issues/299"""
  # We have found that, when invoking `sv stop python-daemon`, the process
  # in call() isn't killed. Therefore, we need to explicitly kill it and
  # all of its children.
  #
  # We hope that pid recycling is not that fast.
  try:
    with open(LAST_PID_FILE, 'r') as f:
      pid = int(f.read().strip())
      os.killpg(pid, signal.SIGKILL)
  except:  # pylint: disable=bare-except
    pass
  finally:
    try:
      os.remove(LAST_PID_FILE)
    except:  # pylint: disable=bare-except
      pass
