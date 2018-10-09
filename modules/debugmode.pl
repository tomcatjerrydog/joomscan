#start Debug Mode Checker

$source=$ua->get("$target/")->decoded_content;
if ($source =~ /Joomla\! Debug Console/g or $source =~ /xdebug\.org\/docs\/all_settings/g) {
	dprint("Checking Debug Mode status");
	tprint("Debug mode Enabled : $target/");
	$result{'wrong_config'} .= $split_str;
	$result{'wrong_config'} .= "debug mode : $target\n";
}

#end Debug Mode Checker

