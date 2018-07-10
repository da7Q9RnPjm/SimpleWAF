<?php

require_once("class.swaf.php");
$sec = new SimpleWAF();
$sec->secureMe(true);

echo "Just an test page ...";