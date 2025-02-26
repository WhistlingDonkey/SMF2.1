<?php

/**
 * This is an internal development file. It should NOT be included in
 * any SMF distribution packages.
 *
 * This file updates version numbers and copyright years in any SMF
 * files that need it in order to prepare for a new release.
 *
 * To automatically increment the version number, run this file on the
 * CLI like this:
 *
 *     php -f other/update_version_numbers.php
 *
 * To manually specify a version string, do this:
 *
 *     php -f other/update_version_numbers.php 'version_string_here'
 *
 * Note: manually specifying a version string should only be needed
 * when changing from alpha to beta, from beta to release candidate, or
 * from release candidate to release version.
 *
 *
 * Simple Machines Forum (SMF)
 *
 * @package SMF
 * @author Simple Machines https://www.simplemachines.org
 * @copyright 2022 Simple Machines and individual contributors
 * @license https://www.simplemachines.org/about/smf/license.php BSD
 *
 * @version 2.1.2
 */

// Obviously, set this to the name of the release branch in question
$release_branch = 'release-2.1';

// The root directory of the working tree for this Git repository
$basedir = dirname(__DIR__);

// Do nothing if on wrong branch or working tree is dirty
if (trim(shell_exec('cd "' . $basedir . '"; if [[ "$(git rev-parse --abbrev-ref HEAD)" != "' . $release_branch . '" || -n "$(git status --porcelain)" ]]; then echo "abort"; else echo; fi')) !== '')
{
	die('Could not continue. Wrong branch or dirty working tree.');
}

// Matches all standard SMF version strings
$version_regex = '\d+\.\d+[. ]?(?:(?:(?<= )(?>RC|Beta |Alpha ))?\d+)?';

// Get previous version based on the most recent Git tag
// This assumes we are using proper sematic versioning in our tags
$prev_version = ltrim(trim(shell_exec('cd "' . $basedir . '"; git checkout "' . $release_branch . '" &>/dev/null; git describe --tags --abbrev=0')), 'v');

// Was the new version passed as a command line argument?
if (!empty($argv[1]))
{
	$new_version = trim($argv[1]);

	if (!preg_match('~^' . $version_regex . '$~', $new_version))
		die('Provided version string is invalid: ' . $new_version);
}
// Normal case: just increment the patch number
else
{
	$new_version = array_pad(explode('.', $prev_version), 3, 0);

	$new_version[2]++;

	if (!is_numeric($new_version[1]))
	{
		$new_version[1] = str_replace(array('-', 'ALPHA', 'BETA'), array(' ', 'Alpha', 'Beta'), strtoupper($new_version[1]));

		$new_version[1] .= (strpos($new_version[1], 'RC') !== false ? '' : ' ') . $new_version[2];

		unset($new_version[2]);
	}

	$new_version = implode('.', $new_version);
}

$year = date_format(date_create(), 'Y');

// These need to be updated for every new version, even if they have not otherwise changed
$always_update = array('index.php', 'cron.php', 'proxy.php', 'SSI.php', 'other/install.php', 'other/upgrade.php', 'other/upgrade-helper.php', 'other/Settings.php', 'other/Settings_bak.php');

// Update SMF_VERSION and SMF_SOFTWARE_YEAR
foreach ($always_update as $file)
{
	$content = $original_content = file_get_contents("$basedir/$file");

	$content = preg_replace("~define\('SMF_VERSION', '" . $version_regex . "'\);~", "define('SMF_VERSION', '$new_version');", $content);
	$content = preg_replace("~define\('SMF_SOFTWARE_YEAR', '\d{4}'\);~", "define('SMF_SOFTWARE_YEAR', '$year');", $content);

	if ($content !== $original_content)
		file_put_contents("$basedir/$file", $content);
}

// Update license blocks
$license_pattern = '~(' . preg_quote('* @package SMF
 * @author Simple Machines https://www.simplemachines.org
 * @copyright ') . ')\d{4}(' . preg_quote(' Simple Machines and individual contributors
 * @license https://www.simplemachines.org/about/smf/license.php BSD
 *
 * @version ') . ')' . $version_regex . '~';

$lang_pattern = '~// Version: \K' . $version_regex . '~';

$files = array_unique(array_merge($always_update, array_filter(explode("\n", shell_exec('cd "' . $basedir . '"; git diff --name-only v' . $prev_version . '...HEAD | grep -E \'\.php$\' | sort')), 'strlen')));
foreach ($files as $file)
{
	$content = $original_content = file_get_contents("$basedir/$file");

	if (preg_match($license_pattern, $content))
	{
		$content = preg_replace($license_pattern, '${1}' . $year . '${2}' . $new_version, $content);
	}
	elseif (preg_match($lang_pattern, $content))
	{
		$content = preg_replace($lang_pattern, $new_version, $content);
	}
	else
	{
		echo "Could not update $file\n";
		continue;
	}

	if ($content !== $original_content)
		file_put_contents("$basedir/$file", $content);
}

// Update SMF_LANG_VERSION
preg_match($lang_pattern, file_get_contents("$basedir/Themes/default/languages/index.english.php"), $matches);

$lang_version = $matches[0];

$content = $original_content = file_get_contents("$basedir/other/upgrade.php");
$content = preg_replace("~define\('SMF_LANG_VERSION', '" . $version_regex . "'\);~", "define('SMF_LANG_VERSION', '$lang_version');", $content);

if ($content !== $original_content)
	file_put_contents("$basedir/other/upgrade.php", $content);

?>