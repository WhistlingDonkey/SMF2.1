<?php


/**
 * Contains all the functionality required to be able to edit the server security
 * settings. This includes anything from which an error may result in the forum
 * destroying itself in a firey fury.
 *
 * Adding options to one of the setting screens isn't hard. Call prepareDBSettingsContext;
 * The basic format for a checkbox is:
 * 		array('check', 'nameInModSettingsAndSQL'),
 * And for a text box:
 * 		array('text', 'nameInModSettingsAndSQL')
 * (NOTE: You have to add an entry for this at the bottom!)
 *
 * In these cases, it will look for $txt['nameInModSettingsAndSQL'] as the description,
 * and $helptxt['nameInModSettingsAndSQL'] as the help popup description.
 *
 * Here's a quick explanation of how to add a new item:
 *
 * - A text input box.  For textual values.
 * 		array('text', 'nameInModSettingsAndSQL', 'OptionalInputBoxWidth'),
 * - A text input box.  For numerical values.
 * 		array('int', 'nameInModSettingsAndSQL', 'OptionalInputBoxWidth'),
 * - A text input box.  For floating point values.
 * 		array('float', 'nameInModSettingsAndSQL', 'OptionalInputBoxWidth'),
 * - A large text input box. Used for textual values spanning multiple lines.
 * 		array('large_text', 'nameInModSettingsAndSQL', 'OptionalNumberOfRows'),
 * - A check box.  Either one or zero. (boolean)
 * 		array('check', 'nameInModSettingsAndSQL'),
 * - A selection box.  Used for the selection of something from a list.
 * 		array('select', 'nameInModSettingsAndSQL', array('valueForSQL' => $txt['displayedValue'])),
 * 		Note that just saying array('first', 'second') will put 0 in the SQL for 'first'.
 * - A password input box. Used for passwords, no less!
 * 		array('password', 'nameInModSettingsAndSQL', 'OptionalInputBoxWidth'),
 * - A permission - for picking groups who have a permission.
 * 		array('permissions', 'manage_groups'),
 * - A BBC selection box.
 * 		array('bbc', 'sig_bbc'),
 * - A list of boards to choose from
 *  	array('boards', 'likes_boards'),
 *  	Note that the storage in the database is as 1,2,3,4
 *
 * For each option:
 * 	- type (see above), variable name, size/possible values.
 * 	  OR make type '' for an empty string for a horizontal rule.
 *  - SET preinput - to put some HTML prior to the input box.
 *  - SET postinput - to put some HTML following the input box.
 *  - SET invalid - to mark the data as invalid.
 *  - PLUS you can override label and help parameters by forcing their keys in the array, for example:
 *  	array('text', 'invalidlabel', 3, 'label' => 'Actual Label')
 *
 * Simple Machines Forum (SMF)
 *
 * @package SMF
 * @author Simple Machines https://www.simplemachines.org
 * @copyright 2021 Simple Machines and individual contributors
 * @license https://www.simplemachines.org/about/smf/license.php BSD
 *
 * @version 2.1 RC4
 */

use SMF\Cache\CacheApi;
use SMF\Cache\CacheApiInterface;

if (!defined('SMF'))
	die('No direct access...');

require_once($sourcedir . '/ManageServer.php');
	
/**
 * This is the main dispatcher. Sets up all the available sub-actions, all the tabs and selects
 * the appropriate one based on the sub-action.
 *
 * Requires the admin_forum permission.
 * Redirects to the appropriate function based on the sub-action.
 *
 * Uses edit_settings adminIndex.
 */
function ModifySecurity()
{
	global $context, $txt, $boarddir;

	// This is just to keep the database password more secure.
	isAllowedTo('admin_forum');

	// Load up all the tabs...
	$context[$context['admin_menu_name']]['tab_data'] = array(
		'title' => $txt['admin_security_settings'],
		'help' => 'securitysettings',
		'description' => $txt['admin_secure_settings'],
	);

	checkSession('request');

	// The settings are in here, I swear!
	loadLanguage('ManageSettings');

	$context['page_title'] = $txt['admin_security_settings'];
	$context['sub_template'] = 'show_settings';

	$subActions = array(
		'securityforum' => 'ModifyGeneralSecuritySettings',
		'securityheaders' => 'ModifyHTTPSecurityHeadersSettings',
		'securitysri' => 'ModifyHTTPSecuritySRISettings',
		'securitycors' => 'ModifyHTTPSecurityCORSSettings',
	);

	// By default we're editing the core settings
	$_REQUEST['sa'] = isset($_REQUEST['sa']) && isset($subActions[$_REQUEST['sa']]) ? $_REQUEST['sa'] : 'securityforum';
	$context['sub_action'] = $_REQUEST['sa'];

	// Warn the user if there's any relevant information regarding Settings.php.
	$settings_not_writable = !is_writable($boarddir . '/Settings.php');
	$settings_backup_fail = !@is_writable($boarddir . '/Settings_bak.php') || !@copy($boarddir . '/Settings.php', $boarddir . '/Settings_bak.php');

	if ($settings_not_writable)
		$context['settings_message'] = array(
			'label' => $txt['settings_not_writable'],
			'tag' => 'div',
			'class' => 'centertext strong'
		);
	elseif ($settings_backup_fail)
		$context['settings_message'] = array(
			'label' => $txt['admin_backup_fail'],
			'tag' => 'div',
			'class' => 'centertext strong'
		);

	$context['settings_not_writable'] = $settings_not_writable;

	call_integration_hook('integrate_server_settings', array(&$subActions));

	// Call the right function for this sub-action.
	call_helper($subActions[$_REQUEST['sa']]);
}

/**
 * Settings really associated with general security aspects.
 *
 * @param bool $return_config Whether or not to return the config_vars array (used for admin search)
 * @return void|array Returns nothing or returns the $config_vars array if $return_config is true
 */
function ModifyGeneralSecuritySettings($return_config = false)
{
	global $txt, $scripturl, $context;

	$config_vars = array(
		array('int', 'failed_login_threshold'),
		array('int', 'loginHistoryDays', 'subtext' => $txt['zero_to_disable']),
		'',

		array('check', 'securityDisable'),
		array('check', 'securityDisable_moderate'),
		'',

		// Reactive on email, and approve on delete
		array('check', 'send_validation_onChange'),
		array('check', 'approveAccountDeletion'),
		'',

		// Password strength.
		array(
			'select',
			'password_strength',
			array(
				$txt['setting_password_strength_low'],
				$txt['setting_password_strength_medium'],
				$txt['setting_password_strength_high']
			)
		),
		array('check', 'enable_password_conversion'),
		'',

		// Reporting of personal messages?
		array('check', 'enableReportPM'),
		'',

		array('check', 'allow_cors'),
		array('check', 'allow_cors_credentials'),
		array('text', 'cors_domains'),
		array('text', 'cors_headers'),
		'',

		array(
			'select',
			'frame_security',
			array(
				'SAMEORIGIN' => $txt['setting_frame_security_SAMEORIGIN'],
				'DENY' => $txt['setting_frame_security_DENY'],
				'DISABLE' => $txt['setting_frame_security_DISABLE']
			)
		),
		'',

		array(
			'select',
			'proxy_ip_header',
			array(
				'disabled' => $txt['setting_proxy_ip_header_disabled'],
				'autodetect' => $txt['setting_proxy_ip_header_autodetect'],
				'HTTP_X_FORWARDED_FOR' => 'X-Forwarded-For',
				'HTTP_CLIENT_IP' => 'Client-IP',
				'HTTP_X_REAL_IP' => 'X-Real-IP',
				'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP'
			)
		),
		array('text', 'proxy_ip_servers'),
	);

	call_integration_hook('integrate_general_security_settings', array(&$config_vars));

	if ($return_config)
		return $config_vars;

	// Saving?
	if (isset($_GET['save']))
	{
		saveDBSettings($config_vars);
		$_SESSION['adm-save'] = true;

		call_integration_hook('integrate_save_general_security_settings');

		writeLog();
		redirectexit('action=admin;area=serversettings;sa=security;' . $context['session_var'] . '=' . $context['session_id']);
	}

	$context['post_url'] = $scripturl . '?action=admin;area=securitysettings;save;sa=security';
	$context['settings_title'] = $txt['security_settings'];

	prepareDBSettingContext($config_vars);
}

/**
 * HTTP Response Header settings associated with HTTP security aspects.
 *
 * @param bool $return_config Whether or not to return the config_vars array (used for admin search)
 * @return void|array Returns nothing or returns the $config_vars array if $return_config is true
 */
function ModifyHTTPSecurityHeadersSettings($return_config = false)
{
	global $txt, $scripturl, $context;

		$context['settings_message'] = array('label' => $txt['httpsec_headers_desc'], 'tag' => 'div', 'class' => 'noticebox') ;
		
		$config_vars = array(
		
		array('large_text', 'httpsec_content-security-policy', 'rows' => 7),
		'',
		array(
			'select',
			'httpsec_nonce',
			array(
				'disable' => $txt['httpsec_nonce_disable'],
				'use_php' => $txt['httpsec_nonce_php'],
				'use_server' => $txt['httpsec_nonce_server']
				),
			),
		array(
			'select',
			'httpsec_nonce_applies',
			array(
				'inline' => $txt['httpsec_nonce_inline'],
				'all' => $txt['httpsec_nonce_all']
				),
			),
		array('text', 'httpsec_csp_nonce_pattern', 'size' => 30),
		array('text', 'httpsec_server_nonce_param', 'size' => 30),
		'',
		array(
			'select',
			'httpsec_strict-transport-security',
			array(
				'disable' => $txt['httpsec_strict-transport-security_disable'],
				'enable' => $txt['httpsec_strict-transport-security_enable'],
			)
		),
		array('int', 'httpsec_hsts_max-age', 'size' => 10),
		array('check', 'httpsec_hsts_include_subdomains'),
		array('check', 'httpsec_hsts_enable_preload'),
		'',
		array(
			'select',
			'httpsec_x-frame-options',
			array(
				'disable' => $txt['httpsec_x-frame-options_disable'],
				'sameorigin' => $txt['httpsec_x-frame-options_sameorigin'],
				'deny' => $txt['httpsec_x-frame-options_deny']
			)
		),
		'',
		array(
			'select',
			'httpsec_x-content-type-options',
			array(
				'disable' => $txt['httpsec_x-content-type-options_disable'],
				'nosniff' => $txt['httpsec_x-content-type-options_nosniff']
			)
		),
		'',	
		array(
			'select',
			'httpsec_referrer-policy',
			array(
				'disable' => $txt['httpsec_referrer-policy_disable'],
				'no-referrer' => $txt['httpsec_referrer-policy_no-referrer'],
				'no-referrer-when-downgrade' => $txt['httpsec_referrer-policy_no-referrer-when-downgrade'],
				'origin' => $txt['httpsec_referrer-policy_origin'],
				'origin-when-cross-origin' => $txt['httpsec_referrer-policy_origin-when-cross-origin'],				
				'same-origin' => $txt['httpsec_referrer-policy_same-origin'],
				'strict-origin' => $txt['httpsec_referrer-policy_strict-origin'],
				'strict-origin-when-cross-origin' => $txt['httpsec_referrer-policy_strict-origin-when-cross-origin']
			)
		),
		'',
		array('text', 'httpsec_clear-site-data', 'size' => 30),
		'',
		array(
			'select',
			'httpsec_cross-origin-embedder-policy',
			array(
				'disable' => $txt['httpsec_coep_disable'],
				'unsafe-none' => $txt['httpsec_coep_unsafe-none'],
				'require-corp' => $txt['httpsec_coep_require-corp']
			)
		),
		'',
		array(
			'select',
			'httpsec_cross-origin-opener-policy',
			array(
				'disable' => $txt['httpsec_coop_disable'],
				'unsafe-none' => $txt['httpsec_coop_unsafe-none'],
				'same-origin' => $txt['httpsec_coop_same-origin'],
				'same-origin-allow-popups' => $txt['httpsec_coop_soap']
			)
		),
		'',
		array(
			'select',
			'httpsec_cross-origin-resource-policy',
			array(
				'disable' => $txt['httpsec_corp_disable'],
				'same-site' => $txt['httpsec_corp_same-site'],
				'same-origin' => $txt['httpsec_corp_same-origin'],
				'cross-origin' => $txt['httpsec_corp_cross-origin']
			)
		),
		'',
		array('large_text', 'httpsec_custom_headers', 'rows' => 7),
		);

	call_integration_hook('integrate_httpsec_settings', array(&$config_vars));

	if ($return_config)
		return $config_vars;

	// Saving?
	if (isset($_GET['save']))
	{
		saveDBSettings($config_vars);
		$_SESSION['adm-save'] = true;

		call_integration_hook('integrate_save_httpsec_header_settings');

		writeLog();
		redirectexit('action=admin;area=securitysettings;sa=securityheaders;' . $context['session_var'] . '=' . $context['session_id']);
	}

	$context['post_url'] = $scripturl . '?action=admin;area=securitysettings;save;sa=securityheaders';
	$context['settings_title'] = $txt['httpsec_headers_settings'];
	
	prepareDBSettingContext($config_vars);
	
}


/**
 * HTTP CORS settings associated with HTTP security aspects.
 *
 * @param bool $return_config Whether or not to return the config_vars array (used for admin search)
 * @return void|array Returns nothing or returns the $config_vars array if $return_config is true
 */
function ModifyHTTPSecurityCORSSettings($return_config = false)
{
	global $txt, $scripturl, $context;
	
		$config_vars = array(
		array('check', 'allow_cors'),
		array('check', 'allow_cors_credentials'),
		array('text', 'cors_domains', 'size' => 30),
		array('text', 'cors_headers', 'size' => 30),
		);
		
	call_integration_hook('integrate_cors_settings', array(&$config_vars));

	if ($return_config)
		return $config_vars;

	// Saving?
	if (isset($_GET['save']))
	{
		saveDBSettings($config_vars);
		$_SESSION['adm-save'] = true;

		call_integration_hook('integrate_save_cors_settings');

		writeLog();
		redirectexit('action=admin;area=securitysettings;sa=securitycors;' . $context['session_var'] . '=' . $context['session_id']);
	}

	$context['post_url'] = $scripturl . '?action=admin;area=securitysettings;save;sa=securitycors';
	$context['settings_title'] = $txt['httpsec_cors_settings'];

	prepareDBSettingContext($config_vars);
	
}

/**
 * HTTP SRI settings associated with HTTP security aspects.
 *
 * @param bool $return_config Whether or not to return the config_vars array (used for admin search)
 * @return void|array Returns nothing or returns the $config_vars array if $return_config is true
 */
function ModifyHTTPSecuritySRISettings($return_config = false)
{
	global $txt, $scripturl, $context;
	
	$context['settings_message'] = array('label' => $txt['httpsec_sri_core_desc'], 'tag' => 'div', 'class' => 'noticebox');
	
		$config_vars = array(
		array(
			'text',
			'httpsec_jquery_sri_hash',
			'size' => 50
			),
		array(
			'select',
			'httpsec_jquery_sri_auth',
			array(
				'anonymous' => $txt['httpsec_jquery_auth_anonymous'],
				'use-credentials' => $txt['httpsec_jquery_auth_credential']
				),
			)
		);

	call_integration_hook('integrate_httpsec_sri_settings', array(&$config_vars));

	if ($return_config)
		return $config_vars;

	// Saving?
	if (isset($_GET['save']))
	{
		saveDBSettings($config_vars);
		$_SESSION['adm-save'] = true;

		call_integration_hook('integrate_save_http_security_sri_settings');

		writeLog();
		redirectexit('action=admin;area=securitysettings;sa=securitysri;' . $context['session_var'] . '=' . $context['session_id']);
	}

	$context['post_url'] = $scripturl . '?action=admin;area=securitysettings;save;sa=securitysri';
	$context['settings_title'] = $txt['httpsec_sri_settings'];

	prepareDBSettingContext($config_vars);
	
}

?>