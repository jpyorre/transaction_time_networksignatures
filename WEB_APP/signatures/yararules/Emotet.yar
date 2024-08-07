rule emotet : post {
meta:
  author = "Josh Pyorre"
  date = "2022-09-21"
  description = "Emotet"
strings:
  $type="POST"
  $user_agent="Mozilla/5.0 (Windows NT 6."
  $content="--|00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|"
  $referer="Referer|0d 0a|"
condition:
  ($user_agent) or ($type) or ($content) or ($referer)
}


/*
$mz = { 4d 5a }
  $cmovnz={ 0f 45 fb 0f 45 de }
  $mov_esp_0={ C7 04 24 00 00 00 00 89 44 24 0? }
  $_eax={ 89 E? 8D ?? 24 ?? 89 ?? FF D0 83 EC 04 }
condition:
  ($mz at 0 and $_eax in( 0x2854..0x4000)) and ($cmovnz or $mov_esp_0)

alert http $HOME_NET any -> $EXTERNAL_NET [7080,8080,443,80,4143,995,21,50000,20,8090,8443,990,22] (msg:"ET MALWARE Win32/Emotet CnC Activity (POST) M10"; flow:established,to_server; content:"POST"; http.uri; content:!"."; content:!"&"; content:!"-"; http.user_agent; content:"Mozilla/5.0 (Windows NT 6."; startswith; content:"|3b 20|"; distance:1; within:2; http.request_body; content:!".zip"; content:!".png"; content:!".jp"; content:!".exe"; content:"--|00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; fast_pattern; http.content_len; byte_test:0,<,8000,0,string,dec; byte_test:0,>,500,0,string,dec; http.header_names; content:"|0d 0a|User-Agent|0d 0a|Accept|0d 0a|Accept-Language|0d 0a|Accept-Encoding|0d 0a|"; startswith; content:"Referer|0d 0a|"; distance:0; reference:md5,ba2e4a231652f8a492feb937b1e96e71; classtype:trojan-activity; sid:2030868; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2020_09_14, deployment Perimeter, signature_severity Major, updated_at 2020_09_14;)
*/
