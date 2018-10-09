sub visit_component{
	my $num = scalar(@_);
	if ($num != 2){
		fprint("parameter count error");	
	}
	my $com_url = @_[0];
	my $mod_name = @_[1];
	my @file_list = ('WS_FTP.LOG','README.txt','readme.txt','README.md','readme.md','LICENSE.TXT','license.txt','LICENSE.txt','licence.txt','CHANGELOG.txt','changelog.txt','MANIFEST.xml','manifest.xml','error_log','error.log');;
	
	my $response=$ua->get($com_url);
	my $headers  = $response->headers();
	my $content_type =$headers->content_type();
	
	if ($response->status_line =~ /200/g ) {

		$result{'plugin'} .= "$split_str$com_url";

		$source=$response->decoded_content;
		if ($source =~ /<title>Index of/g or $source =~ /Last modified<\/a>/g) {
			$result{'dir_list'} .= $split_str;
			$result{'dir_list'} .= "$com_url\n";
		}
		
		$btf=1;

		#components/com_
		foreach $ffile(@file_list){
			$response=$ua->get("$com_url/$ffile");
			my $headers  = $response->headers();
			my $content_type =$headers->content_type();
			if ($response->status_line =~ /200/g ) {
				chomp $ffile;
				$result{'interest_file'} .= $split_str;
				$result{'interest_file'} .= "$com_url/$ffile";			
			}
		}
		
		#Version finder
		$xm=$mod_name;
		$xm=~ s/com_//g;

		$response=$ua->get("$com_url/$xm.xml");
		my $headers  = $response->headers();
		$sourcer=$response->decoded_content;
		if ($response->status_line =~ /200/g ) {
			$sourcer =~ /type=\"component\" version=\"(.*?)\"/;
			$comversion = $1;
			$result{'plugin'}.="\nInstalled version : $comversion";
			
		}
		
		open(my $FB,"exploit/db/comvul.txt");
		
		while( my $row = <$FB>)  {
			my @matches;
			while ($row =~/\[(.*?)\]/g) {
			push @matches, $1;
			}
			
			if ( @matches[1] eq $xm) {
				print "matches1:@matches[1]\n";
				print "xm name : $xm\n";
				$result{'plugin_vul'} .= $split_str;
				#compare install version vs fixed version
				if($comversion =~ /\./ and @matches[6] =~ /\./){
					print "comversion : $comversion\n";
					print "matches6 : @matches[6]\n";
					$result{'plugin_vul'} .="$comversion\n";
					$a=$comversion;
					$b=@matches[6];
					print "a is : $a\n";
					print "b is : $b\n";
					if(!&version_compare("$a","$b") == -1) {

						$result{'plugin_vul'} .= "[!] We found vulnerable component\n";
					}else{
						#$result{'plugin_vul'} .="[!] We found the component \"com_$xm\", but since the component version was not available we cannot ensure that it's vulnerable, please test it yourself.\n";
					}
								  
				}else{
					print "comversion : $comversion\n";
					print "matches6 : @matches[6]\n";
					$result{'plugin_vul'} .="[!] We found the component \"com_$xm\", but since the component version was not available we cannot ensure that it's vulnerable, please test it yourself.\n";
				}
							
				$result{'plugin_vul'} .= "Title : ". @matches[0] . "\n" if @matches[0] !~ /-/;
				$result{'plugin_vul'} .=  "Exploit date : ". @matches[2]. "\n" if @matches[2] !~ /-/;
				$result{'plugin_vul'} .=  "Reference : http://www.cvedetails.com/cve/CVE-". @matches[3]. "\n" if @matches[3] !~ /-/ and @matches[3] !~ /\,/;
				if(index(@matches[3], ',') != -1){
					print 123;
					@pp=split(/\,/,@matches[3]);
					$tmtm="";
					foreach $tt(@pp){
						$result{'plugin_vul'} .= "Reference : http://www.cvedetails.com/cve/CVE-$tt\n";
					}
				}
				$result{'plugin_vul'}.=  "Reference : https:///www.exploit-db.com/exploits/". @matches[5]. "\n" if @matches[5] !~ /-/;
				$result{'plugin_vul'}.=  "Component : ". @matches[4]. "\n" if @matches[4] !~ /-/;
				$result{'plugin_vul'}.=  "Fixed in : ". @matches[6]. "\n" if @matches[6] !~ /-/;
				#$tmp.=  "Introduced in : ". @matches[7]. "\n" if @matches[7] !~ /-/;				 
			} 
		
		}
	}
}