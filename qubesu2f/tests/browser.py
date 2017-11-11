#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017  Wojtek Porczyk <woju@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# pylint: disable=missing-docstring

import os
import pathlib
import unittest

import pkg_resources
import selenium.webdriver
import selenium.common.exceptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions, ui

from .. import __author__

TEST_URI = 'https://demo.yubico.com/u2f'
TEST_USERAGENT = (
    'Mozilla 5.0 (qubesu2f tests; contact {!r})'.format(__author__))

TEST_USERNAME = 'qubesu2f_{}'.format(os.getpid())
TEST_PASSPHRASE = TEST_USERNAME

class TC_00_Browser(unittest.TestCase):
    def do_selenium_test(self, factory):
        # do not use subTest, since we need register to succeed before auth
        for tab, form in (
                ('Register', 'enroll-form'),
                ('Login', 'sign-form')):

            driver = factory()
            driver.get(TEST_URI)

            try:
                driver.find_element_by_link_text(tab).click()
                form = driver.find_element_by_name(form)
                form.find_element_by_name('username').send_keys(TEST_USERNAME)
                form.find_element_by_name('password').send_keys(TEST_PASSPHRASE)
                form.submit()

                # keep timeout at 40, to allow for browser timeout of about 30 s
                # to actually happen and catch its message
                hero_unit = ui.WebDriverWait(driver, 40).until(
                    expected_conditions.presence_of_element_located((
                    By.CLASS_NAME, 'hero-unit')))

                if 'failed' in hero_unit.find_element_by_tag_name('h2').text:
                    tb = hero_unit.find_element_by_tag_name('pre').text
                    self.fail('{}: {}'.format(
                        tab, tb.rstrip().rsplit('\n', 1)[-1]))

            except selenium.common.exceptions.TimeoutException:
                self.fail('{}: timeout'.format(tab))

            finally:
                driver.quit()

    def get_firefox_driver(self):
        profile = selenium.webdriver.FirefoxProfile()
        profile.add_extension(pkg_resources.resource_filename(__package__,
            'u2f_support_add_on-1.0.1-fx-linux.xpi'))
        self.addCleanup(pkg_resources.cleanup_resources)
        profile.set_preference('general.useragent.override', TEST_USERAGENT)

        # I don't know why it extracts binaries without executable bit
        for path in (pathlib.Path(profile.extensionsDir)
                / 'u2f4moz@prefiks.org' / 'bin').glob('*/u2f'):
            path.chmod(0o755)

        return selenium.webdriver.Firefox(firefox_profile=profile)

    @staticmethod
    def get_chrome_driver():
        return selenium.webdriver.Chrome()


    def test_001_firefox(self):
        self.do_selenium_test(self.get_firefox_driver)

    @unittest.skip('net::ERR_BLOCKED_BY_CLIENT')
    def test_002_chrome(self):
        self.do_selenium_test(self.get_chrome_driver)
