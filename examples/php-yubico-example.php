<?php
## this example requires php-yubico: http://code.google.com/p/php-yubico/
require_once '/opt/Auth_Yubico-2.3/Yubico.php';
require_once './yubi_functions.php';

## configuration
$config = array(
	'api_id' => '1',
	'api_key' => '2l0alAfbbfG1R8Da77Ypig==',
	'api_url' => 'localhost:88/cgi-bin/yubiverify2.0.tcl');

## create and configure Auth_Yubico class
$yubi = new Auth_Yubico($config['api_id'], $config['api_key']);
$yubi->setURLpart($config['api_url']);
$yubi->addURLpart($config['api_url']);

## get input from somewhere
$input = 'ehc.d.kndcyccpckkgygeninyjpjkuiceuiducggbdtp';
echo "input: $input\n";

## un-dvorak input
if (!($input = normalize_modhex($input)))
	die("cannot find keymap\n");

## check yubikey token aka public identity
if (($parsed_otp = $yubi->parsePasswordOTP($input)) === false)
	die("invalid OTP\n");
if ($parsed_otp['prefix'] != 'djiehevlhiti') ## this check is usually done via database
	die("invalid yubikey user\n");

## verify OTP
$verify = $yubi->verify($input, null, true);
echo "verify: $verify\n";
if (PEAR::isError($verify))
	echo "==[ auth failed ]==\n" .$yubi->_response."\n";
else
	echo "==[ success ]==\n";
