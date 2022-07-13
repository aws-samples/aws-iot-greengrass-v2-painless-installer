import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from edge import install_gg


def mock_check_output_oracle_7(args, stderr):
    if args[0] == "java":
        return 'java version "1.7.0_79"' \
               '\nJava(TM) SE Runtime Environment (build 1.7.0_79-b15)' \
               '\nJava HotSpot(TM) Client VM (build 24.79-b02, mixed mode)'
    elif args[0] == "ldd":
        return 'ldd (GNU libc) 2.24' \
               '\nCopyright (C) 2017 Free Software Foundation, Inc.' \
               '\nThis is free software; see the source for copying conditions.  There is NO' \
               '\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.' \
               '\nWritten by Roland McGrath and Ulrich Drepper.'
    else:
        raise RuntimeError("Bad args: {}".format(args))


def mock_check_output_openjdk_11(args, stderr):
    if args[0] == "java":
        return 'openjdk 11.0.3 2019-04-16' \
               '\nOpenJDK Runtime Environment (build 11.0.3+7-Ubuntu-1ubuntu218.04.1)' \
               '\nOpenJDK 64-Bit Server VM (build 11.0.3+7-Ubuntu-1ubuntu218.04.1, mixed mode, sharing)'
    elif args[0] == "ldd":
        return 'ldd (GNU libc) 2.26' \
               '\nCopyright (C) 2017 Free Software Foundation, Inc.' \
               '\nThis is free software; see the source for copying conditions.  There is NO' \
               '\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.' \
               '\nWritten by Roland McGrath and Ulrich Drepper.'
    else:
        raise RuntimeError("Bad args: {}".format(args))


def force_linux():
    return install_gg.check_requirements_linux()


check_sudoers_copy = install_gg.check_sudoers


def sudoers_good1():
    return check_sudoers_copy(fname="./sudoers.good1")


def sudoers_good2():
    return check_sudoers_copy(fname="./sudoers.good2")


def sudoers_bad1():
    return check_sudoers_copy(fname="./sudoers.bad1")


class TestCase(unittest.TestCase):

    @patch("edge.install_gg.check_sudoers")
    @patch('os.geteuid', return_value=1)
    @patch('edge.install_gg.check_requirements_darwin')
    @patch('subprocess.check_output')
    def test01(self, output, darwin, pgeteuid, psudoers):
        output.side_effect = mock_check_output_oracle_7
        darwin.side_effect = force_linux
        psudoers.side_effect = sudoers_bad1
        results = install_gg.check_requirements()
        expect = {'ps': True, 'sudo': True, 'sh': True, 'kill': True, 'cp': True, 'chmod': True, 'rm': True,
                  'ln': True, 'echo': True, 'exit': False, 'id': True, 'uname': True, 'grep': True,
                  'systemctl': False, 'useradd': False, 'groupadd': False, 'usermod': False, 'java': False,
                  'glibc': False, 'root': False, 'sudoers': False, 'tmp directory': True}
        self.assertDictEqual(expect, results)

    @patch("edge.install_gg.check_sudoers")
    @patch('os.geteuid', return_value=0)
    @patch('edge.install_gg.check_requirements_darwin')
    @patch('subprocess.check_output')
    def test02(self, output, darwin, pgeteuid, psudoers):
        output.side_effect = mock_check_output_openjdk_11
        darwin.side_effect = force_linux
        psudoers.side_effect = sudoers_good1
        results = install_gg.check_requirements()
        expect = {'ps': True, 'sudo': True, 'sh': True, 'kill': True, 'cp': True, 'chmod': True, 'rm': True,
                  'ln': True, 'echo': True, 'exit': False, 'id': True, 'uname': True, 'grep': True,
                  'systemctl': False, 'useradd': False, 'groupadd': False, 'usermod': False, 'java': True,
                  'glibc': True, 'root': True, 'sudoers': True, 'tmp directory': True}
        self.assertDictEqual(expect, results)
        psudoers.side_effect = sudoers_good2
        results = install_gg.check_requirements()
        self.assertDictEqual(expect, results)

    def test03(self):
        self.assertFalse(install_gg.check_sudoers("./sudoers.bad1"))
        self.assertTrue(install_gg.check_sudoers("./sudoers.good1"))
        self.assertTrue(install_gg.check_sudoers("./sudoers.good2"))


if __name__ == "__main__":
    unittest.main()
