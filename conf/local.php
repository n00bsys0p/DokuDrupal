<?php

/**
 *  Set your MySQL database connection settings in
 *  conf/mysql.conf.php
 **/
require_once('mysql.conf.php');

/**
 * The following settings must be configured for your
 * specific instance of Drupal. The defaults should work for
 * a default installation with no table prefix. This assumes
 * a relative Drupal installation path of '../drupal/'
 **/
$conf['SQLFindRoles']    = "SELECT r.name FROM users_roles u INNER JOIN
                            role r WHERE u.uid='%{uid}' && u.rid=r.rid";
$conf['SQLFindPWHash']   = "SELECT pass FROM users WHERE name='%{user}'";
$conf['SQLValidateUser'] = "SELECT name from users where name='%{user}'";
$conf['SQLFindSession']  = "SELECT u.uid,u.name,u.mail,s.hostname FROM users u
                            INNER JOIN sessions s ON u.uid=s.uid WHERE s.sid='%{sessioncookie}'
                            && u.status=1";
$conf['DrupalRoot']      = '../drupal/';

?>
