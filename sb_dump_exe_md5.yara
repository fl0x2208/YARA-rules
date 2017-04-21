import "hash"

rule shadow_broker_md5 {
    
    meta:
	description = "Shadow_Borker_MD5"

    condition:
	uint16(0) == 0x5A4D and filesize < 500KB and 
	hash.md5(0, filesize) == "2dee8e8fccd2407677fbcde415fdf27e" or 	
	hash.md5(0, filesize) == "7e1a081a93d07705bd5ed2d2919c4eea" or 	
	hash.md5(0, filesize) == "195efb4a896e41fe49395c3c165a5d2e" or 			
        hash.md5(0, filesize) == "0bc136522423099f72dbf8f67f99e7d8" or    	
	hash.md5(0, filesize) == "52933e70e022054153aa37dfd44bcafa" or  	
	hash.md5(0, filesize) == "76237984993d5bae7779a1c3fbe2aac2" or 		
	hash.md5(0, filesize) == "305a1577298d2ca68918c3840fccc958" or  
	hash.md5(0, filesize) == "b4cb23d33c82bb66a7edcfe85e9d5361" or  	
	hash.md5(0, filesize) == "91ab4b74e86e7db850d7c127eeb5d473" or 	
	hash.md5(0, filesize) == "1d2db6d8d77c2e072db34ca7377722be" or 	
	hash.md5(0, filesize) == "8d3ffa58cb0dc684c9c1d059a154cf43" or   	
	hash.md5(0, filesize) == "4420f8917dc320a78d2ef14136032f69" or   	
	hash.md5(0, filesize) == "2a8d437f0b9ffac482750fe052223c3d" or   	
	hash.md5(0, filesize) == "84986365e9dfbde4fdd80c0e7481354f" or 	
	hash.md5(0, filesize) == "dc53bd258f6debef8604d441c85cb539" or 		
	hash.md5(0, filesize) == "05f8f70d2ef15a375d4d9dee14072404" or 
	hash.md5(0, filesize) == "be8dc61dd7890f8eb4bdc9b1c43e76f7" or 
	hash.md5(0, filesize) == "c24315b0585b852110977dacafe6c8c1" or  
	hash.md5(0, filesize) == "4b5c89998a4f48c11f4a2f0591ab2293" or 
	hash.md5(0, filesize) == "59268a3cbe5f2ab0b26d4de239dff68d" or 
	hash.md5(0, filesize) == "1ec381aa04945298ae85bed76b2194af" or 
	hash.md5(0, filesize) == "4c266bf82c5e28e20edb52d557a40e1d" or  
	hash.md5(0, filesize) == "12dea3524d5c7937102075c781a3ef85" or 
	hash.md5(0, filesize) == "9f285065c8315da2de01a48e8ca7e7be" or 
	hash.md5(0, filesize) == "4f6a975ddd6ed3903b8129441240b46f" or 
	hash.md5(0, filesize) == "9d6f88030fd7775129d947ad1dd9c689" or 
	hash.md5(0, filesize) == "b012614bf00aecfbee2a7707e21c2841" or 
	hash.md5(0, filesize) == "460bc972466813b80c9be900e56302b6" or 
	hash.md5(0, filesize) == "3a4223a09a928606723fd36186179934" or 
	hash.md5(0, filesize) == "866612476e5707c3c4d34d6527f1495a" or 
	hash.md5(0, filesize) == "958cbaaf1e7f89501d442ab4bf596e67" or 
	hash.md5(0, filesize) == "601fb299e706301b0b0a1b3d6ac1bfa5" or 
	hash.md5(0, filesize) == "8c80dd97c37525927c1e549cb59bcbf3" or 
	hash.md5(0, filesize) == "d2fb01629fa2a994fbd1b18e475c9f23"
}

/*
MD5 (Easybee-1.0.1.exe) = 2dee8e8fccd2407677fbcde415fdf27e
MD5 (Easypi-3.1.0.exe) = 7e1a081a93d07705bd5ed2d2919c4eea
MD5 (Eclipsedwing-1.5.2.exe) = 195efb4a896e41fe49395c3c165a5d2e
MD5 (Educatedscholar-1.0.0.exe) = 0bc136522423099f72dbf8f67f99e7d8
MD5 (Emeraldthread-3.0.0.exe) = 52933e70e022054153aa37dfd44bcafa
MD5 (Emphasismine-3.4.0.exe) = 76237984993d5bae7779a1c3fbe2aac2
MD5 (Englishmansdentist-1.2.0.exe) = 305a1577298d2ca68918c3840fccc958
MD5 (Erraticgopher-1.0.1.exe) = b4cb23d33c82bb66a7edcfe85e9d5361
MD5 (Eskimoroll-1.1.1.exe) = 91ab4b74e86e7db850d7c127eeb5d473
MD5 (Esteemaudit-2.1.0.exe) = 1d2db6d8d77c2e072db34ca7377722be
MD5 (Eternalromance-1.3.0.exe) = 8d3ffa58cb0dc684c9c1d059a154cf43
MD5 (Eternalromance-1.4.0.exe) = 4420f8917dc320a78d2ef14136032f69
MD5 (Eternalsynergy-1.0.1.exe) = 2a8d437f0b9ffac482750fe052223c3d
MD5 (Ewokfrenzy-2.0.0.exe) = 84986365e9dfbde4fdd80c0e7481354f
MD5 (Explodingcan-2.0.2.exe) = dc53bd258f6debef8604d441c85cb539
MD5 (Darkpulsar-1.1.0.exe) = 05f8f70d2ef15a375d4d9dee14072404
MD5 (Mofconfig-1.0.0.exe) = be8dc61dd7890f8eb4bdc9b1c43e76f7
MD5 (Doublepulsar-1.3.1.exe) = c24315b0585b852110977dacafe6c8c1
MD5 (Jobadd-1.1.1.exe) = 4b5c89998a4f48c11f4a2f0591ab2293
MD5 (Jobdelete-1.1.1.exe) = 59268a3cbe5f2ab0b26d4de239dff68d
MD5 (Joblist-1.1.1.exe) = 1ec381aa04945298ae85bed76b2194af
MD5 (Pcdlllauncher-2.3.1.exe) = 4c266bf82c5e28e20edb52d557a40e1d
MD5 (Processlist-1.1.1.exe) = 12dea3524d5c7937102075c781a3ef85
MD5 (Regdelete-1.1.1.exe) = 9f285065c8315da2de01a48e8ca7e7be
MD5 (Regenum-1.1.1.exe) = 4f6a975ddd6ed3903b8129441240b46f
MD5 (Regread-1.1.1.exe) = 9d6f88030fd7775129d947ad1dd9c689
MD5 (Regwrite-1.1.1.exe) = b012614bf00aecfbee2a7707e21c2841
MD5 (Rpcproxy-1.0.1.exe) = 460bc972466813b80c9be900e56302b6
MD5 (Smbdelete-1.1.1.exe) = 3a4223a09a928606723fd36186179934
MD5 (Smblist-1.1.1.exe) = 866612476e5707c3c4d34d6527f1495a
MD5 (Smbread-1.1.1.exe) = 958cbaaf1e7f89501d442ab4bf596e67
MD5 (Smbwrite-1.1.1.exe) = 601fb299e706301b0b0a1b3d6ac1bfa5
MD5 (Eternalblue-2.2.0.exe) = 	  8c80dd97c37525927c1e549cb59bcbf3
MD5 (Eternalchampion-2.0.0.exe) = d2fb01629fa2a994fbd1b18e475c9f23
*/
