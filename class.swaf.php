<?php

class SimpleWAF {
	var $log_file = "logs";
	var $telegram_notice = true;
	var $telegram_api = "341621460:AAFVjPUtbqmyB6DylwUrP5Wi345lmMKpUnM";
	var $telegram_chatid = "212541915";
	var $protect_unset_global = true;
	var $protect_range_ip_deny = false;
	var $protect_range_ip_spam = false;
	var $protect_url = true;
	var $protect_request_server = true;
	var $protect_santy = true;
	var $protect_bots = true;
	var $protect_request_method = true;
	var $protect_dos = true;
	var $protect_union_sql = true;
	var $protect_click_attack = true;
	var $protect_xss = true;
	var $protect_cookies = true;
	var $protect_post = true;
	var $protect_get = true;
	var $protect_server_ovh = true;
	var $protect_server_kimsufi = true;
	var $protect_server_dedibox = true;
	var $protect_server_digicube = true;
	var $protect_server_ovh_by_ip = true;
	var $protect_server_dedibox_by_ip = true;
	var $protect_server_digicube_by_ip = true;
	var $protect_upload = true;
	var $protect_upload_maxsize = 25; // Max file size in mb
	var $protect_upload_sanitise_fn = true;

	private function msgWarning($msg) {
		$show = "<title>Blocked</title>
		<center>
			<img src=\"http://img.4plebs.org/boards/tg/image/1403/85/1403850647688.png\" width=\"150\">
			<br /><br />
			<i><b>[ ".$msg." ]</b></i>
		</center>";
		return $show;
	}

	function sendNotification($chatid, $text) {
		return file_get_contents("https://api.telegram.org/bot".$this->telegram_api."/sendMessage?chat_id=".$chatid."&text=".$text);
	}

	private function unset_globals() {
		if ( ini_get('register_globals') ) {
			$allow = array('_ENV' => 1, '_GET' => 1, '_POST' => 1, '_COOKIE' => 1, '_FILES' => 1, '_SERVER' => 1, '_REQUEST' => 1, 'GLOBALS' => 1);
			foreach ($GLOBALS as $key => $value) {
				if ( ! isset( $allow[$key] ) ) unset( $GLOBALS[$key] );
			}
		}
	}

	private function get_env($st_var) {
		global $HTTP_SERVER_VARS;
		if(isset($_SERVER[$st_var])) {
			return strip_tags( $_SERVER[$st_var] );
		} elseif(isset($_ENV[$st_var])) {
			return strip_tags( $_ENV[$st_var] );
		} elseif(isset($HTTP_SERVER_VARS[$st_var])) {
			return strip_tags( $HTTP_SERVER_VARS[$st_var] );
		} elseif(getenv($st_var)) {
			return strip_tags(getenv($st_var));
		} elseif(function_exists('apache_getenv') && apache_getenv($st_var, true)) {
			return strip_tags(apache_getenv($st_var, true));
		}
		return '';
	}

	private function get_referer() {
		if( $this->get_env('HTTP_REFERER') )
			return $this->get_env('HTTP_REFERER');
		return 'no referer';
	}

	private function get_ip() {
		if ($this->get_env('HTTP_X_FORWARDED_FOR')) {
			return $this->get_env('HTTP_X_FORWARDED_FOR');
		} elseif ($this->get_env('HTTP_CLIENT_IP')) {
			return $this->get_env('HTTP_CLIENT_IP');
		} else {
			return $this->get_env('REMOTE_ADDR');
		}
	}

	private function get_user_agent() {
		if($this->get_env('HTTP_USER_AGENT'))
			return $this->get_env('HTTP_USER_AGENT');
		return 'none';
	}

	private function get_query_string() {
		if($this->get_env('QUERY_STRING'))
			return str_replace('%09', '%20', $this->get_env('QUERY_STRING'));
		return '';
	}

	private function get_request_method() {
		if($this->get_env('REQUEST_METHOD'))
			return $this->get_env('REQUEST_METHOD');
		return 'none';
	}

	private function get_host() {
		if ($this->protect_server_ovh === true OR $this->protect_server_kimsufi === true OR $this->protect_server_dedibox === true OR $this->protect_server_digicube === true ) {
			if (@empty($_SESSION['$this->gethostbyaddr'])) {
				return $_SESSION['$this->gethostbyaddr'] = @gethostbyaddr($this->get_ip());
			} else {
				return strip_tags($_SESSION['$this->gethostbyaddr']);
			}
		}
	}

	private function logs($type) {
		$f = fopen(dirname(__FILE__).'/'.$this->log_file.'.txt', 'a');
		$msg = date('j-m-Y H:i:s')." | $type | IP: ".$this->get_ip()." | DNS: ".gethostbyaddr($this->get_ip())." | Agent: ".$this->get_user_agent()." | URL: ".$_SERVER['REQUEST_URI']." | Referer: ".$this->get_referer();
		fputs($f, $msg."\n\n");
		fclose($f);
		if($this->telegram_notice === true) {
			$this->sendNotification($this->telegram_chatid, $msg);
		}
	}

	private function check_upload() {
		$f_uploaded = array();
		$f_uploaded = $this->fetch_uploads();
		$tmp = '';
		if ( $this->protect_upload == false ) {
			$tmp = '';
			foreach ($f_uploaded as $key => $value) {
				if (! $f_uploaded[$key]['name']) { continue; }
				$tmp .= $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes) ';
	      }
	      if ( $tmp ) {
				$this->logs('Blocked file upload attempt', rtrim($tmp, ' '), 3, 0);
				die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
			}
		} else {
			foreach ($f_uploaded as $key => $value) {
				if (! $f_uploaded[$key]['name']) { continue; }
				if ( $f_uploaded[$key]['size'] > $this->protect_upload_maxsize ) {
					$this->logs('Attempt to upload a file > ' . ($this->protect_upload_maxsize / 1024) .
						' KB' , $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes)', 1, 0);
					die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
				}
				$data = '';

				if (preg_match('/\.ht(?:access|passwd)|(?:php\d?|\.user)\.ini|\.ph(?:p([34x7]|5\d?)?|t(ml)?)(?:\.|$)/', $f_uploaded[$key]['name']) ) {
					$this->logs('Attempt to upload a script or system file', $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes)', 3, 0);
					die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
				}
				$data = file_get_contents($f_uploaded[$key]['tmp_name']);

				if (preg_match('`^\x7F\x45\x4C\x46`', $data) ) {
					$this->logs('Attempt to upload an executable file (ELF)', $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes)', 3, 0);
					die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
				}
					// MZ header :
				if (preg_match('`^\x4D\x5A`', $data) ) {
					$this->logs('Attempt to upload an executable file (Microsoft MZ header)', $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes)', 3, 0);
					die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
				}


				if (preg_match('`(<\?(?i:php\s|=[\s\x21-\x7e]{10})|#!/(?:usr|bin)/.+?\s|\s#include\s+<[\w/.]+?>|\W\$\{\s*([\'"])\w+\2)`', $data, $match) ) {
					$this->logs('Attempt to upload a script', $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes), pattern: '. $match[1], 3, 0);
					die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
				}

				if ( preg_match( '`<svg.*>.*?(<[a-z].+?\bon[a-z]{3,29}\b\s*=.{5}|<script.*?>.+?</script\s*>|data:image/svg\+xml;base64|javascript:|ev:event=).*?</svg\s*>`s', $data, $match ) ) {
					$this->logs('Attempt to upload an SVG file containing Javascript/XML events', $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes), pattern: '. $match[1], 3, 0);
					die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
				}

				if ( $f_uploaded[$key]['size'] > 67 && $f_uploaded[$key]['size'] < 129 ) {
					if ( empty($data) ) {
						$data = file_get_contents( $f_uploaded[$key]['tmp_name'] );
					}
					if ( preg_match('`^X5O!P%@AP' . '\[4\\\PZX54\(P\^\)7CC\)7}\$EIC' .
					                'AR-STANDARD-ANTIVI' . 'RUS-TEST-FILE!\$H' . '\+H\*' .
					                '[\x09\x10\x13\x20\x1A]*`', $data) ) {
						$this->logs('EICAR Standard Anti-Virus Test File blocked', $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes)', 3, 0);
						die($this->msgWarning('Unauthorized file upload detected ! stop it ...'));
					}
				}

				if ( $this->protect_upload_sanitise_fn == true ) {
					$substitute = 'X';
					$tmp = '';
					$f_uploaded_name = $f_uploaded[$key]['name'];
					$f_uploaded[$key]['name'] = preg_replace('/[^\w\.\-]/i', $substitute, $f_uploaded[$key]['name'], -1, $count);

					if ($count) {
						$tmp = ' (sanitising '. $count . ' char. from filename)';
						$_FILES = $this->sanitize_filename( $_FILES, $f_uploaded_name, $f_uploaded[$key]['name'] );
					}
				}
				$this->logs('File upload detected, no action taken' . $tmp , $f_uploaded[$key]['name'] . ' (' . number_format($f_uploaded[$key]['size']) . ' bytes)', 5, 0);
			}
		}
	}

	private function fetch_uploads() {
		global $file_buffer, $upload_array, $prop_key;
		$upload_array = array();
		foreach( $_FILES as $f_key => $f_value ) {
			foreach( $f_value as $prop_key => $prop_value ) {
				// Fetch all but 'error':
				if (! in_array( $prop_key, array( 'name', 'type', 'tmp_name', 'size' ) ) ) { continue; }
				$file_buffer = $f_key;
				if ( is_array( $_FILES[$f_key][$prop_key] ) ) {
					$this->recursive_upload( $_FILES[$f_key][$prop_key] );
				} else {
					if (! empty( $_FILES[$f_key][$prop_key] ) ) {
						$upload_array[$f_key][$prop_key] = $_FILES[$f_key][$prop_key];
					}
				}
			}
		}
		return $upload_array;
	}

	private function recursive_upload( $data ) {
		global $file_buffer, $upload_array, $prop_key;
		foreach( $data as $data_key => $data_value ) {
			if ( is_array( $data_value ) ) {
				$file_buffer .= "_{$data_key}";
				$this->recursive_upload( $data_value );
			} else {
				if ( empty( $data_value ) ) { continue; }
				$upload_array["{$file_buffer}_{$data_key}"][$prop_key] = $data_value;
			}
		}
	}

	private function sanitize_filename( $array, $key, $value ) {
		array_walk_recursive(
			$array, function( &$v, $k ) use ( $key, $value ) {
				if (! empty( $v ) && $v == $key ) { $v = $value; }
			}
		);
		return $array;
	}

	public function secureMe($activate) {
		$regex_union = "'#\w?\s?union\s\w*?\s?(select|all|distinct|insert|update|drop|delete)#is'";
		if($activate == true) {
			$this->check_upload();
			if($this->protect_unset_global == true) {
				$this->unset_globals();
			}
			if($this->protect_server_ovh === true) {
				if (stristr($this->get_host(),'ovh') ) {
					$this->logs('OVH Server list');
					die($this->msgWarning('Protection OVH Server active, this IP range is not allowed !'));
				}
			}

			if($this->protect_server_ovh_by_ip === true) {
				$ip = explode('.', $this->get_ip());
				if ( $ip[0].'.'.$ip[1] == '87.98' or  $ip[0].'.'.$ip[1] == '91.121' or  $ip[0].'.'.$ip[1] == '94.23' or $ip[0].'.'.$ip[1] == '213.186' or  $ip[0].'.'.$ip[1] == '213.251' ) {
					$this->logs('OVH Server IP');
					die($this->msgWarning('Protection OVH Server active, this IP range is not allowed !'));
				}
			}

			if($this->protect_server_kimsufi === true) {
				if (stristr($this->get_host(),'kimsufi')) {
					$this->logs('KIMSUFI Server list');
					die($this->msgWarning('Protection KIMSUFI Server active, this IP range is not allowed !'));
				}
			}

			if($this->protect_server_dedibox === true) {
				if ( stristr( $this->get_host() ,'dedibox') ) {
					$this->logs( 'DEDIBOX Server list' );
					die($this->msgWarning('Protection DEDIBOX Server active, this IP range is not allowed !'));
				}
			}

			if($this->protect_server_dedibox_by_ip === true) {
				$ip = explode('.', $this->get_ip());
				if ($ip[0].'.'.$ip[1] == '88.191') {
					$this->logs('DEDIBOX Server IP');
					die($this->msgWarning('Protection DEDIBOX Server active, this IP is not allowed !'));
				}
			}

			if($this->protect_server_digicube === true) {
				if (stristr( $this->get_host() ,'digicube')) {
					$this->logs('DIGICUBE Server list');
					die($this->msgWarning('Protection DIGICUBE Server active, this IP range is not allowed !'));
				}
			}

			if($this->protect_server_digicube_by_ip === true) {
				$ip = explode('.', $this->get_ip() );
				if ($ip[0].'.'.$ip[1] == '95.130') {
					$this->logs('DIGICUBE Server IP');
					die($this->msgWarning('Protection DIGICUBE Server active, this IP is not allowed !'));
				}
			}

			if($this->protect_range_ip_spam === true) {
				$ip_array = array('24', '186', '189', '190', '200', '201', '202', '209', '212', '213', '217', '222' );
				$range_ip = explode('.', $this->get_ip());
				if (in_array( $range_ip[0], $ip_array)) {
					$this->logs('IPs Spam list');
					die($this->msgWarning('Protection SPAM IPs active, this IP range is not allowed !'));
				}
			}

			if($this->protect_range_ip_deny === true) {
				$ip_array = array('0', '1', '2', '5', '10', '14', '23', '27', '31', '36', '37', '39', '42', '46', '49', '50', '100', '101', '102', '103', '104', '105', '106', '107', '114', '172', '176', '177', '179', '181', '185', '192', '223', '224');
				$range_ip = explode('.', $this->get_ip());
				if (in_array( $range_ip[0], $ip_array)) {
					$this->logs('IPs reserved list');
					die($this->msgWarning('Protection died IPs active, this IP range is not allowed !'));
				}
			}

			if($this->protect_cookies === true) {
				$ct_rules = Array('applet', 'base', 'bgsound', 'blink', 'embed', 'expression', 'frame', 'javascript', 'layer', 'link', 'meta', 'object', 'onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate', 'onblur', 'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup', 'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 'onmovestart', 'onpaste', 'onpropertychange', 'onreadystatechange', 'onreset', 'onresize', 'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit', 'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop', 'onsubmit', 'onunload', 'script', 'style', 'title', 'vbscript', 'xml');
				if($this->protect_cookies === true) {
					foreach($_COOKIE as $value) {
						$check = str_replace($ct_rules, '*', $value);
						if($value != $check) {
							$this->logs('Cookie protect');
							unset($value);
							die($this->msgWarning('Cookie attack detected ! stop it ...'));
						}
					}
				}
				if($this->protect_post === true) {
					foreach($_POST as $value) {
						$check = str_replace($ct_rules, '*', $value);
						if($value != $check) {
							$this->logs('POST protect');
							unset($value);
							die($this->msgWarning('POST attack detected ! stop it ...'));
						}
					}
				}
				if($this->protect_get === true) {
					foreach($_GET as $value) {
						$check = str_replace($ct_rules, '*', $value);
						if($value != $check) {
							$this->logs('GET protect');
							unset($value);
							die($this->msgWarning('GET attack detected ! stop it ...'));
						}
					}
				}
			}

			if ( $this->protect_url === true ) {
				$ct_rules = array( 'absolute_path', 'ad_click', 'alert(', 'alert%20', ' and ', 'basepath', 'bash_history', '.bash_history', 'cgi-', 'chmod(', 'chmod%20', '%20chmod', 'chmod=', 'chown%20', 'chgrp%20', 'chown(', '/chown', 'chgrp(', 'chr(', 'chr=', 'chr%20', '%20chr', 'chunked', 'cookie=', 'cmd', 'cmd=', '%20cmd', 'cmd%20', '.conf', 'configdir', 'config.php', 'cp%20', '%20cp', 'cp(', 'diff%20', 'dat?', 'db_mysql.inc', 'document.location', 'document.cookie', 'drop%20', 'echr(', '%20echr', 'echr%20', 'echr=', '}else{', '.eml', 'esystem(', 'esystem%20', '.exe',  'exploit', 'file\://', 'fopen', 'fwrite', '~ftp', 'ftp:', 'ftp.exe', 'getenv', '%20getenv', 'getenv%20', 'getenv(', 'grep%20', '_global', 'global_', 'global[', 'http:', '_globals', 'globals_', 'globals[', 'grep(', 'g\+\+', 'halt%20', '.history', '?hl=', '.htpasswd', 'http_', 'http-equiv', 'http/1.', 'http_php', 'http_user_agent', 'http_host', '&icq', 'if{', 'if%20{', 'img src', 'img%20src', '.inc.php', '.inc', 'insert%20into', 'ISO-8859-1', 'ISO-', 'javascript\://', '.jsp', '.js', 'kill%20', 'kill(', 'killall', '%20like', 'like%20', 'locate%20', 'locate(', 'lsof%20', 'mdir%20', '%20mdir', 'mdir(', 'mcd%20', 'motd%20', 'mrd%20', 'rm%20', '%20mcd', '%20mrd', 'mcd(', 'mrd(', 'mcd=', 'mod_gzip_status', 'modules/', 'mrd=', 'mv%20', 'nc.exe', 'new_password', 'nigga(', '%20nigga', 'nigga%20', '~nobody', 'org.apache', '+outfile+', '%20outfile%20', '*/outfile/*',' outfile ','outfile', 'password=', 'passwd%20', '%20passwd', 'passwd(', 'phpadmin', 'perl%20', '/perl', 'phpbb_root_path','*/phpbb_root_path/*','p0hh', 'ping%20', '.pl', 'powerdown%20', 'rm(', '%20rm', 'rmdir%20', 'mv(', 'rmdir(', 'phpinfo()', '<?php', 'reboot%20', '/robot.txt' , '~root', 'root_path', 'rush=', '%20and%20', '%20xorg%20', '%20rush', 'rush%20', 'secure_site, ok', 'select%20', 'select from', 'select%20from', '_server', 'server_', 'server[', 'server-info', 'server-status', 'servlet', 'sql=', '<script', '<script>', '</script','script>','/script', 'switch{','switch%20{', '.system', 'system(', 'telnet%20', 'traceroute%20', '.txt', 'union%20', '%20union', 'union(', 'union=', 'vi(', 'vi%20', 'wget', 'wget%20', '%20wget', 'wget(', 'window.open', 'wwwacl', ' xor ', 'xp_enumdsn', 'xp_availablemedia', 'xp_filelist', 'xp_cmdshell', '$_request', '$_get', '$request', '$get',  '&aim', '/etc/password','/etc/shadow', '/etc/groups', '/etc/gshadow', '/bin/ps', 'uname\x20-a', '/usr/bin/id', '/bin/echo', '/bin/kill', '/bin/', '/chgrp', '/usr/bin', 'bin/python', 'bin/tclsh', 'bin/nasm', '/usr/x11r6/bin/xterm', '/bin/mail', '/etc/passwd', '/home/ftp', '/home/www', '/servlet/con', '?>', '.txt');
				$check = str_replace($ct_rules, '*', $this->get_query_string() );
				if( $this->get_query_string() != $check ) {
					$this->logs( 'URL protect' );
					die($this->msgWarning('Protection url active, string not allowed !'));
				}
			}

			/** Posting from other servers in not allowed */
			if ( $this->protect_request_server === true ) {
				if ( $this->get_request_method() == 'POST' ) {
					if (isset($_SERVER['HTTP_REFERER'])) {
						if ( ! stripos( $_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST'], 0 ) ) {
							$this->logs( 'Posting another server' );
							die($this->msgWarning('Posting from another server not allowed !'));
						}
					}
				}
			}

			if ( $this->protect_santy === true ) {
				$ct_rules = array('rush','highlight=%','perl','chr(','pillar','visualcoder','sess_');
				$check = str_replace($ct_rules, '*', strtolower($_SERVER['REQUEST_URI']) );
				if( strtolower($_SERVER['REQUEST_URI']) != $check ) {
					$this->logs( 'Santy' );
					die($this->msgWarning('Attack Santy detected ! Stop it ...'));
				}
			}

			/** protection bots */
			if ( $this->protect_bots === true ) {
				$ct_rules = array( '@nonymouse', 'addresses.com', 'ideography.co.uk', 'adsarobot', 'ah-ha', 'aktuelles', 'alexibot', 'almaden', 'amzn_assoc', 'anarchie', 'art-online', 'aspseek', 'assort', 'asterias', 'attach', 'atomz', 'atspider', 'autoemailspider', 'backweb', 'backdoorbot', 'bandit', 'batchftp', 'bdfetch', 'big.brother', 'black.hole', 'blackwidow', 'blowfish', 'bmclient', 'boston project', 'botalot', 'bravobrian', 'buddy', 'bullseye', 'bumblebee ', 'builtbottough', 'bunnyslippers', 'capture', 'cegbfeieh', 'cherrypicker', 'cheesebot', 'chinaclaw', 'cicc', 'civa', 'clipping', 'collage', 'collector', 'copyrightcheck', 'cosmos', 'crescent', 'custo', 'cyberalert', 'deweb', 'diagem', 'digger', 'digimarc', 'diibot', 'directupdate', 'disco', 'dittospyder', 'download accelerator', 'download demon', 'download wonder', 'downloader', 'drip', 'dsurf', 'dts agent', 'dts.agent', 'easydl', 'ecatch', 'echo extense', 'efp@gmx.net', 'eirgrabber', 'elitesys', 'emailsiphon', 'emailwolf', 'envidiosos', 'erocrawler', 'esirover', 'express webpictures', 'extrac', 'eyenetie', 'fastlwspider', 'favorg', 'favorites sweeper', 'fezhead', 'filehound', 'filepack.superbr.org', 'flashget', 'flickbot', 'fluffy', 'frontpage', 'foobot', 'galaxyBot', 'generic', 'getbot ', 'getleft', 'getright', 'getsmart', 'geturl', 'getweb', 'gigabaz', 'girafabot', 'go-ahead-got-it', 'go!zilla', 'gornker', 'grabber', 'grabnet', 'grafula', 'green research', 'harvest', 'havindex', 'hhjhj@yahoo', 'hloader', 'hmview', 'homepagesearch', 'htmlparser', 'hulud', 'http agent', 'httpconnect', 'httpdown', 'http generic', 'httplib', 'httrack', 'humanlinks', 'ia_archiver', 'iaea', 'ibm_planetwide', 'image stripper', 'image sucker', 'imagefetch', 'incywincy', 'indy', 'infonavirobot', 'informant', 'interget', 'internet explore', 'infospiders',  'internet ninja', 'internetlinkagent', 'interneteseer.com', 'ipiumbot', 'iria', 'irvine', 'jbh', 'jeeves', 'jennybot', 'jetcar', 'joc web spider', 'jpeg hunt', 'justview', 'kapere', 'kdd explorer', 'kenjin.spider', 'keyword.density', 'kwebget', 'lachesis', 'larbin',  'laurion(dot)com', 'leechftp', 'lexibot', 'lftp', 'libweb', 'links aromatized', 'linkscan', 'link*sleuth', 'linkwalker', 'libwww', 'lightningdownload', 'likse', 'lwp','mac finder', 'mag-net', 'magnet', 'marcopolo', 'mass', 'mata.hari', 'mcspider', 'memoweb', 'microsoft url control', 'microsoft.url', 'midown', 'miixpc', 'minibot', 'mirror', 'missigua', 'mister.pix', 'mmmtocrawl', 'moget', 'mozilla/2', 'mozilla/3.mozilla/2.01', 'mozilla.*newt', 'multithreaddb', 'munky', 'msproxy', 'nationaldirectory', 'naverrobot', 'navroad', 'nearsite', 'netants', 'netcarta', 'netcraft', 'netfactual', 'netmechanic', 'netprospector', 'netresearchserver', 'netspider', 'net vampire', 'newt', 'netzip', 'nicerspro', 'npbot', 'octopus', 'offline.explorer', 'offline explorer', 'offline navigator', 'opaL', 'openfind', 'opentextsitecrawler', 'orangebot', 'packrat', 'papa foto', 'pagegrabber', 'pavuk', 'pbwf', 'pcbrowser', 'personapilot', 'pingalink', 'pockey', 'program shareware', 'propowerbot/2.14', 'prowebwalker', 'proxy', 'psbot', 'psurf', 'puf', 'pushsite', 'pump', 'qrva', 'quepasacreep', 'queryn.metasearch', 'realdownload', 'reaper', 'recorder', 'reget', 'replacer', 'repomonkey', 'rma', 'robozilla', 'rover', 'rpt-httpclient', 'rsync', 'rush=', 'searchexpress', 'searchhippo', 'searchterms.it', 'second street research', 'seeker', 'shai', 'sitecheck', 'sitemapper', 'sitesnagger', 'slysearch', 'smartdownload', 'snagger', 'spacebison', 'spankbot', 'spanner', 'spegla', 'spiderbot', 'spiderengine', 'sqworm', 'ssearcher100', 'star downloader', 'stripper', 'sucker', 'superbot', 'surfwalker', 'superhttp', 'surfbot', 'surveybot', 'suzuran', 'sweeper', 'szukacz/1.4', 'tarspider', 'takeout', 'teleport', 'telesoft', 'templeton', 'the.intraformant', 'thenomad', 'tighttwatbot', 'titan', 'tocrawl/urldispatcher','toolpak', 'traffixer', 'true_robot', 'turingos', 'turnitinbot', 'tv33_mercator', 'uiowacrawler', 'urldispatcherlll', 'url_spider_pro', 'urly.warning ', 'utilmind', 'vacuum', 'vagabondo', 'vayala', 'vci', 'visualcoders', 'visibilitygap', 'vobsub', 'voideye', 'vspider', 'w3mir', 'webauto', 'webbandit', 'web.by.mail', 'webcapture', 'webcatcher', 'webclipping', 'webcollage', 'webcopier', 'webcopy', 'webcraft@bea', 'web data extractor', 'webdav', 'webdevil', 'webdownloader', 'webdup', 'webenhancer', 'webfetch', 'webgo', 'webhook', 'web.image.collector', 'web image collector', 'webinator', 'webleacher', 'webmasters', 'webmasterworldforumbot', 'webminer', 'webmirror', 'webmole', 'webreaper', 'websauger', 'websaver', 'website.quester', 'website quester', 'websnake', 'websucker', 'web sucker', 'webster', 'webreaper', 'webstripper', 'webvac', 'webwalk', 'webweasel', 'webzip', 'wget', 'widow', 'wisebot', 'whizbang', 'whostalking', 'wonder', 'wumpus', 'wweb', 'www-collector-e', 'wwwoffle', 'wysigot', 'xaldon', 'xenu', 'xget', 'x-tractor', 'zeus' );
				$check = str_replace($ct_rules, '*', strtolower($this->get_user_agent()) );
				if( strtolower($this->get_user_agent()) != $check ) {
					$this->logs( 'Bots attack' );
					die($this->msgWarning('Bot attack detected ! stop it ...'));
				}
			}

			if ( $this->protect_request_method === true ) {
				if(strtolower($this->get_request_method())!='get' AND strtolower($this->get_request_method())!='head' AND strtolower($this->get_request_method())!='post' AND strtolower($this->get_request_method())!='put') {
					$this->logs( 'Invalid request' );
					die($this->msgWarning('Invalid request method check ! Stop it ...'));
				}
			}

			if ( $this->protect_dos === true ) {

				if ( $this->get_user_agent() == '-' ) {
					$this->logs( 'Dos attack' );
					die($this->msgWarning('Invalid user agent ! Stop it ...'));
				}
			}

			if ( $this->protect_union_sql === true ) {
				$stop = 0;
				$ct_rules = array( '*/from/*', '*/insert/*', '+into+', '%20into%20', '*/into/*', ' into ', 'into', '*/limit/*', 'not123exists*', '*/radminsuper/*', '*/select/*', '+select+', '%20select%20', ' select ',  '+union+', '%20union%20', '*/union/*', ' union ', '*/update/*', '*/where/*' );
				$check    = str_replace($ct_rules, '*', $this->get_query_string() );
				if( $this->get_query_string() != $check ) $stop++;
				if (preg_match($regex_union, $this->get_query_string())) $stop++;
				if (preg_match('/([OdWo5NIbpuU4V2iJT0n]{5}) /', rawurldecode( $this->get_query_string() ))) $stop++;
				if (strstr(rawurldecode( $this->get_query_string() ) ,'*')) $stop++;
				if ( !empty( $stop ) ) {
					$this->logs( 'Union attack' );
					die($this->msgWarning('Union attack detected ! stop it ......'));
				}
			}

			if ( $this->protect_click_attack === true ) {
				$ct_rules = array( '/*', 'c2nyaxb0', '/*' );
				if( $this->get_query_string() != str_replace($ct_rules, '*', $this->get_query_string() ) ) {
					$this->logs( 'Click attack' );
					die($this->msgWarning('Click attack detected ! stop it .....'));
				}
			}

			if ( $this->protect_xss === true ) {
				$ct_rules = array( 'http\:\/\/', 'https\:\/\/', 'cmd=', '&cmd', 'exec', 'concat', './', '../',  'http:', 'h%20ttp:', 'ht%20tp:', 'htt%20p:', 'http%20:', 'https:', 'h%20ttps:', 'ht%20tps:', 'htt%20ps:', 'http%20s:', 'https%20:', 'ftp:', 'f%20tp:', 'ft%20p:', 'ftp%20:', 'ftps:', 'f%20tps:', 'ft%20ps:', 'ftp%20s:', 'ftps%20:', '.php?url=' );
				$check    = str_replace($ct_rules, '*', $this->get_query_string() );
				if( $this->get_query_string() != $check ) {
					$this->logs( 'XSS attack' );
					die($this->msgWarning('XSS attack detected ! stop it ...'));
				}
			}

		}
	}
}