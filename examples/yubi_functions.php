<?php
function normalize_modhex($s) {
	$keymaps = array(
		'us' => 'cbdefghijklnrtuv',
		'dvorak' => 'jxe.uidchtnbpygk',
		'neo2' => 'äzaleosgnrtbcwhp');
	foreach ($keymaps as $k => $keymap) {
		if (!preg_match('/^['.preg_quote($keymap).']*$/', $s))
			continue;
		if ($k == 'us')
			return $s;
		return strtr($s, $keymap, $keymaps['us']);
	}
	return;
}
