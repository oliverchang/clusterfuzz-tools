"""Test output_transformer."""

import StringIO

from clusterfuzz import output_transformer
from test_libs import helpers


class HiddenTest(helpers.ExtendedTestCase):
  """Test Hidden."""

  def test_print_dot(self):
    """Test printing dot every n characters."""
    self.output = StringIO.StringIO()

    transformer = output_transformer.Hidden()
    transformer.set_output(self.output)
    transformer.process('a' * 1001)
    transformer.flush()

    self.assertEqual('.' * 11 + '\n', self.output.getvalue())
    self.output.close()


class IdentityTest(helpers.ExtendedTestCase):
  """Test Identity."""

  def test_print(self):
    """Test printing dot every n characters."""
    self.output = StringIO.StringIO()

    transformer = output_transformer.Identity()
    transformer.set_output(self.output)
    transformer.process('a' * 1001)
    transformer.flush()

    self.assertEqual('a' * 1001, self.output.getvalue())
    self.output.close()


class NinjaTest(helpers.ExtendedTestCase):
  """Test Ninja."""

  def test_long_chunk(self):
    """Test long chunk."""
    self._test_print(33)

  def test_short_chunk(self):
    """Test short chunk."""
    self._test_print(3)

  def _test_print(self, chunk_size):
    """Test ninja output."""
    data = (
        '[1/100] aaaaaaaaaaa\n'
        '[2/100] bbb\n'
        '[3/100] ccccc\n'
        'FAILED: error\n'
        'more error\n'
        '[4/100] ddd\n')
    self.output = StringIO.StringIO()

    transformer = output_transformer.Ninja()
    transformer.set_output(self.output)
    for i in range(0, len(data), chunk_size):
      transformer.process(data[i:i + chunk_size])
    transformer.flush()

    self.assertEqual(
        ('[1/100] aaaaaaaaaaa' +
         ('\b' * 19) + '[2/100] bbb' + (' ' * 8) +
         ('\b' * 19) + '[3/100] ccccc' + (' ' * 6) + '\n'
         'FAILED: error\n' +
         'more error\n' +
         '[4/100] ddd\n'),
        self.output.getvalue())
    self.output.close()
