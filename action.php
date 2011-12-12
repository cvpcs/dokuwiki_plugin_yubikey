<?php

/**
 * DokuWiki YubiKey plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Austen Dicken <cvpcsm@gmail.com>
 * @version    1.0.0
 */

/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, 
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The license for this software can likely be found here: 
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

/**
 * This program also use the PHP standalone YubiKey class by
 * Tom Corwine (yubico@corwine.org) which is licensed under the GNU
 * General Public LIcense version 2.
 *
 * Its project can be tracked at http://code.google.com/p/yubikey-php-webservice-class/
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN', DOKU_INC . 'lib/plugins/');
if(!defined('DOKU_PLUGIN_YUBIKEY')) define('DOKU_PLUGIN_YUBIKEY', dirname(__FILE__) . '/');

require_once(DOKU_PLUGIN . 'action.php');
require_once(DOKU_PLUGIN_YUBIKEY . 'lib/Yubikey.php');

class action_plugin_yubikey extends DokuWiki_Action_Plugin {

	/**
	 * Return some info
	 */
	function getInfo() {
		return array(
			'author' => 'Austen Dicken',
			'email'  => 'cvpcsm@gmail.com',
			'date'   => '2011-12-10',
			'name'   => 'YubiKey plugin',
			'desc'   => 'Authenticate on a DokuWiki with YubiKey',
			'url'    => 'http://cvpcs.org/projects/web/dokuwiki-plugin-yubikey',
		);
	}

	/**
	 * Register the eventhandlers
	 */
	function register(&$controller) {
		$controller->register_hook('HTML_LOGINFORM_OUTPUT',
			'BEFORE',
			$this,
			'handle_login_form',
			array());
		$controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT',
			'AFTER',
			$this,
			'handle_profile_form',
			array());
		$controller->register_hook('ACTION_ACT_PREPROCESS',
			'BEFORE',
			$this,
			'handle_act_preprocess',
			array());
		$controller->register_hook('TPL_ACT_UNKNOWN',
			'BEFORE',
			$this,
			'handle_act_unknown',
			array());
	}

	/**
	 * Returns the requested URL
	 */
	function _self($do) {
		global $ID;
		return wl($ID, 'do=' . $do, true, '&');
	}

	/**
	 * Redirect the user
	 */
	function _redirect($url) {
		header('Location: ' . $url);
		exit; 
	}

	/**
	 * Handles the yubikey action
	 */
	function handle_act_preprocess(&$event, $param) {
		global $auth, $conf, $ID, $INFO;

		if (!$this->is_setup()) {
			if($conf['useacl'] && $INFO['ismanager']) {
				msg($this->getLang('complete_setup_notice'), 2);
			}

			return;
		}

		$user = $_SERVER['REMOTE_USER'];
        
		// Do not ask the user a password he didn't set
		if ($event->data == 'profile') {
			$conf['profileconfirm'] = 0;
			if (preg_match('!^yubikey:!', $user)) {
				$this->_redirect( $this->_self('yubikey') );
			}
		}

		if ($event->data != 'yubikey' && $event->data != 'logout') {
			// Warn the user to register an account if he's using a not registered YubiKey
			// and if registration is possible
			if (preg_match('!^yubikey:!', $user)) {
				if ($auth && $auth->canDo('addUser') && actionOK('register')) {
					$message = sprintf($this->getLang('complete_registration_notice'), $this->_self('yubikey'));
					msg($message, 2);
				}
			}
		}

		if ($event->data == 'yubikey') {
			// not sure this if it's useful there
			$event->stopPropagation();
			$event->preventDefault();

			if (isset($_POST['mode']) && ($_POST['mode'] == 'login' || $_POST['mode'] == 'add')) {
				// retreive our information
				$yubikey_otp = $_POST['yubikey_otp'];
				$yubikey_cid = $this->getConf('api_client_id');
				$yubikey_sec = $this->getConf('api_secret_key');

				// attempt a login with it
				$yubikey_api = new Yubikey($yubikey_cid, empty($yubikey_sec) ? null : $yubikey_sec);
				$valid = $yubikey_api->verify($yubikey_otp);

				if ($valid) {
					$yubikey = $this->get_yubikey_id($yubikey_otp);

					if (isset($user) && !preg_match('!^yubikey:!', $user)) {
						$result = $this->register_yubikey_association($user,$yubikey);
						if ($result) {
							msg($this->getLang('yubikey_identity_added'), 1);
						}
					} else {
						$authenticate = $this->login_user($yubikey);
						if ($authenticate) {
							// redirect to the page itself (without do=yubikey)
							$this->_redirect(wl($ID));
						}
					}

				} else {
					msg($this->getLang('yubikey_authentication_failed') . ': ' . $yubikey_api->getLastResponse(), -1);
					return;
				}

			} else if (isset($_POST['mode']) && $_POST['mode'] == 'extra') {
				// we register the user on the wiki and associate the account with his YubiKey
				$this->register_user();

			} else if (isset($_POST['mode']) && $_POST['mode'] == 'delete') {
				foreach ($_POST['delete'] as $yubikey => $state) {
					$this->remove_yubikey_association($user, $yubikey);
				}
			}

		}
        
		return; // fall through to what ever action was called
	}

	/**
	 * Create the YubiKey login/complete forms
	 */
	function handle_act_unknown(&$event, $param) {
		global $auth, $conf, $ID, $INFO;

		if (!$this->is_setup()) {
			if($conf['useacl'] && $INFO['ismanager']) {
				msg($this->getLang('complete_setup_notice'), 2);
			}

			return;
		}

		if ($event->data != 'yubikey') {
			return;
		} 

		$event->stopPropagation();
		$event->preventDefault();

		$user = $_SERVER['REMOTE_USER'];

		if (empty($user)) {
			print $this->plugin_locale_xhtml('intro');
			print '<div class="centeralign">'.NL;
			$form = $this->get_yubikey_form('login');
			html_form('register', $form);
			print '</div>'.NL;
		} else if (preg_match('!^yubikey:!', $user)) {
			echo '<h1>', $this->getLang('yubikey_account_fieldset'), '</h1>', NL;
			if ($auth && $auth->canDo('addUser') && actionOK('register')) {
				echo '<p>', $this->getLang('yubikey_complete_text'), '</p>', NL;
				print '<div class="centeralign">'.NL;
				$form = $this->get_yubikey_form('extra');
				html_form('complete', $form);
				print '</div>'.NL;
			} else {
				echo '<p>', sprintf($this->getLang('yubikey_complete_disabled_text'), wl($ID)), '</p>', NL;
			}
		} else {
			echo '<h1>', $this->getLang('yubikeys_title'), '</h1>', NL;
			$yubikeys = $this->get_associations($_SERVER['REMOTE_USER']);
			if (!empty($yubikeys)) {
				echo '<form action="' . $this->_self('yubikey') . '" method="post"><div class="no">';
				echo '<table>';
				foreach ($yubikeys as $yubikey => $user) {
					echo '<tr>';
					echo '<td width="10"><input type="checkbox" name="delete[' . htmlspecialchars($yubikey) . ']"/></td>';
					echo '<td>' . $yubikey . '</td>';
					echo '</tr>';
				}
				echo '</table>';
				echo '<input type="hidden" name="mode" value="delete"/>';
				echo '<input type="submit" value="' . $this->getLang('delete_selected_button') . '" class="button" />';
				echo '</div></form>';
			} else {
				echo '<p>' . $this->getLang('none') . '</p>';
			}
			echo '<h1>' . $this->getLang('add_yubikey_title') . '</h1>';
			print '<div class="centeralign">'.NL;
			$form = new Doku_Form('yubikey__login', script());
			$form->addHidden('do', 'yubikey');
			$form->addHidden('mode', 'add');
			$form->addElement(
				form_makeTextField(
					'yubikey_otp', isset($_POST['yubikey_otp']) ? $_POST['yubikey_otp'] : '',
					$this->getLang('yubikey_otp_label'), 'yubikey__otp', 'block', array('size'=>'50')
				)
			);
			$form->addElement(form_makeButton('submit', '', $this->getLang('add_button')));
			html_form('add', $form);
			print '</div>'.NL;
		}
	}

	/**
	 * Generate the YubiKey login/complete forms
	 */    
	function get_yubikey_form($mode) {
		global $USERINFO, $lang;

		$c = 'block';
		$p = array('size'=>'50');

		$form = new Doku_Form('yubikey__login', script());
		$form->addHidden('id', $_GET['id']);
		$form->addHidden('do', 'yubikey');
		if ($mode == 'extra') {
			$form->startFieldset($this->getLang('yubikey_account_fieldset'));
			$form->addHidden('mode', 'extra');
			$form->addElement(form_makeTextField('nickname', $_REQUEST['nickname'], $lang['user'], null, $c, $p));
			$form->addElement(form_makeTextField('email', $_REQUEST['email'], $lang['email'], '', $c, $p));
			$form->addElement(form_makeTextField('fullname', $_REQUEST['fullname'], $lang['fullname'], '', $c, $p));
			$form->addElement(form_makeButton('submit', '', $this->getLang('complete_button')));
		} else {
			$form->startFieldset($this->getLang('yubikey_login_fieldset'));
			$form->addHidden('mode', 'login');
			$form->addElement(form_makeTextField('yubikey_otp', $_REQUEST['yubikey_otp'], $this->getLang('yubikey_otp_label'), 'yubikey__otp', $c, $p));
			$form->addElement(form_makeButton('submit', '', $lang['btn_login']));
		}
		$form->endFieldset();

		$msg = $this->getLang('login_link_ret');
		$msg = sprintf("<p>$msg</p>", $this->_self('login'));
		$form->addElement($msg);
		return $form;
	}

	/**
	 * Insert link to YubiKey into usual login form
	 */
	function handle_login_form(&$event, $param) {
		global $conf, $INFO;

		if (!$this->is_setup()) {
			if($conf['useacl'] && $INFO['ismanager']) {
				msg($this->getLang('complete_setup_notice'), 2);
			}

			return;
		}

		$msg = $this->getLang('login_link');
		$msg = sprintf("<p>$msg</p>", $this->_self('yubikey'));
		$pos = $event->data->findElementByAttribute('type', 'submit');
		$event->data->insertElement($pos+2, $msg);
	}

	function handle_profile_form(&$event, $param) {
		global $conf, $INFO;

		if (!$this->is_setup()) {
			if($conf['useacl'] && $INFO['ismanager']) {
				msg($this->getLang('complete_setup_notice'), 2);
			}

			return;
		}

		echo '<p>', sprintf($this->getLang('manage_link'), $this->_self('yubikey')), '</p>';
	}
	
	/**
	* Gets called when a YubiKey login was succesful
	*
	* We store available userinfo in Session and Cookie
	*/
	function login_user($yubikey) {
		global $USERINFO, $auth, $conf;

		// look for associations passed from an auth backend in user infos
		$users = $auth->retrieveUsers();
		foreach ($users as $id => $user) {
			if (isset($user['yubikeys'])) {
				foreach ($user['yubikeys'] as $identity) {
					if ($identity == $yubikey) {
						return $this->update_session($id);
					}
				}
			}
		}

		$associations = $this->get_associations();

		// this yubikey is associated with a real wiki user account
		if (isset($associations[$yubikey])) {
			$user = $associations[$yubikey];
			return $this->update_session($user);
		}

		// no real wiki user account associated

		// note that the generated cookie is invalid and will be invalided
		// when the 'auth_security_timeout' expire
		$this->update_session("yubikey:" . $yubikey);

		$redirect_url = $this->_self('yubikey');

		$sregs = array('email', 'nickname', 'fullname');
		foreach ($sregs as $sreg) {
			if (!empty($_GET["yubikey_sreg_$sreg"])) {
				$redirect_url .= "&$sreg=" . urlencode($_GET["yubikey_sreg_$sreg"]);
			}
		}

		// we will advice the user to register a real user account
		$this->_redirect($redirect_url);
	}

	/**
	 * Register the user in DokuWiki user conf,
	 * write the YubiKey association in the YubiKey conf
	 */
	function register_user() {
		global $ID, $lang, $conf, $auth, $yubikey_associations;

		if(!$auth->canDo('addUser')) return false;

		$_POST['login'] = $_POST['nickname'];

		// clean username
		$_POST['login'] = preg_replace('/.*:/','',$_POST['login']);
		$_POST['login'] = cleanID($_POST['login']);
		// clean fullname and email
		$_POST['fullname'] = trim(preg_replace('/[\x00-\x1f:<>&%,;]+/','',$_POST['fullname']));
		$_POST['email']    = trim(preg_replace('/[\x00-\x1f:<>&%,;]+/','',$_POST['email']));

		if (empty($_POST['login']) || empty($_POST['fullname']) || empty($_POST['email'])) {
			msg($lang['regmissing'], -1);
			return false;
		} else if (!mail_isvalid($_POST['email'])) {
			msg($lang['regbadmail'], -1);
			return false;
		}

		// okay try to create the user
		if (!$auth->createUser($_POST['login'], auth_pwgen(), $_POST['fullname'], $_POST['email'])) {
			msg($lang['reguexists'], -1);
			return false;
		}

		$user = $_POST['login'];
		$yubikey = $_SERVER['REMOTE_USER'];

		// if our yubikey id is based on a non-registered user, we need to chunk off the "yubikey:"
		// part of it
		if (preg_match('!^yubikey:!', $yubikey)) {
			$yubikey = substr($yubikey, 8);
		}

		// we update the YubiKey associations array
		$this->register_yubikey_association($user, $yubikey);

		$this->update_session($user);

		// account created, everything OK
		$this->_redirect(wl($ID));
	}
		
	/**
	 * Update user sessions
	 *
	 * Note that this doesn't play well with DokuWiki 'auth_security_timeout' configuration.
	 *
	 * So, you better set it to an high value, like '60*60*24', the user being disconnected
	 * in that case one day after authentication
	 */
	function update_session($user) {
		session_start();

		global $USERINFO, $INFO, $conf, $auth;

		$_SERVER['REMOTE_USER'] = $user;

		$USERINFO = $auth->getUserData($user);
		if (empty($USERINFO)) {
			$USERINFO['pass'] = 'invalid';
			$USERINFO['name'] = 'YubiKey';
			$USERINFO['grps'] = array($conf['defaultgroup'], 'yubikey');
		}

		$pass = PMA_blowfish_encrypt($USERINFO['pass'], auth_cookiesalt());
		auth_setCookie($user, $pass, false);

		// auth data has changed, reinit the $INFO array
		$INFO = pageinfo();

		return true;
	}

	function register_yubikey_association($user, $yubikey) {
		$associations = $this->get_associations();
		if (isset($associations[$yubikey])) {
			msg($this->getLang('yubikey_already_user_error'), -1);
			return false;
		}
		$associations[$yubikey] = $user;
		$this->write_yubikey_associations($associations);
		return true;
	}

	function remove_yubikey_association($user, $yubikey) {
		$associations = $this->get_associations();
		if (isset($associations[$yubikey]) && $associations[$yubikey] == $user) {
			unset($associations[$yubikey]);
			$this->write_yubikey_associations($associations);
			return true;
		}
		return false;
	}

	function write_yubikey_associations($associations) {
		$cfg = '<?php' . "\n";
		foreach ($associations as $id => $login) {
			$cfg .= '$yubikey_associations["' . addslashes($id) . '"] = "' . addslashes($login) . '"' . ";\n";
		}
		file_put_contents(DOKU_CONF.'yubikey.php', $cfg);
		$this->yubikey_associations = $associations;
	}

	function get_associations($username = null) {
		if (isset($this->yubikey_associations)) {
			$yubikey_associations = $this->yubikey_associations;
		} else if (file_exists(DOKU_CONF.'yubikey.php')) {
			// load YubiKey associations array
			$yubikey_associations = array();
			include(DOKU_CONF.'yubikey.php');
			$this->yubikey_associations = $yubikey_associations;
		} else {
			$this->yubikey_associations = $yubikey_associations = $yubikey_associations = array();
		}
		// Maybe is there a better way to filter the array
		if (!empty($username)) {
			$user_yubikey_associations = array();
			foreach ((array)$yubikey_associations as $yubikey => $login) {
				if ($username == $login) {
					$user_yubikey_associations[$yubikey] = $login;
				}
			}
			return $user_yubikey_associations;
		}
		return $yubikey_associations;
	}

	function get_yubikey_id($otp) {
		return substr($otp, 0, 12);
	}

	function is_setup() {
		return $this->getConf('api_client_id') > 0;
	}

}
