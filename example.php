<?php
/*
Example how to call SimpleWAF Class
GitHub: https://github.com/da7Q9RnPjm
*/
require_once("class.swaf.php");
$sec = new SimpleWAF();
$sec->secureMe(true);

echo "Just an test page ...";
