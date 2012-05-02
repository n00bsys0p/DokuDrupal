<?php
/**
 * Drupal 7.x/MySQL authentication backend
 *
 * ----------------------------READ BEFORE USE----------------------------
 * To use this authentication backend, a few additions
 * must be made to your local settings file:
 *
 * $conf['DrupalRoot']          The relative path of your Drupal instance,
 *                              ending in a /, such as '../drupal/'
 *
 * $conf['SQLFindPWHash']       The SQL query to find a password
 *                              hash for a given user.
 *
 * $conf['SQLValidateUser']     The SQL query to find a given user
 *                              by name.
 *
 * $conf['SQLFindSession']      The query to find a session by its SID
 *
 * $conf['SQLFindRoles']        The SQL query to list all roles for a
 *                              given UID
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Alex Shepherd <n00bATNOSPAMn00bsys0p.co.uk>
 *
 * Based on the Dokuwiki MySQL authentication backend by:
 * @author     Andreas Gohr <andi@splitbrain.org>
 * @author     Chris Smith <chris@jalakai.co.uk>
 * @author     Matthias Grimm <matthias.grimmm@sourceforge.net>
 *
 **/

require_once(DOKU_INC.'inc/auth/mysql.class.php');

class auth_drupal7 extends auth_mysql {

    /**
     * Constructor
     *
     * Heavily modified from the original auth_mysql
     * constructor written by Matthias Grimm.
     *
     * @author  Alex Shepherd  <n00b@n00bsys0p.co.uk>
     **/
    function auth_drupal7() {
      global $conf;
      $this->cnf          = $conf['auth']['mysql'];

      if (method_exists($this, 'auth_basic'))
        parent::auth_basic();

      if(!function_exists('mysql_connect')) {
        if ($this->cnf['debug'])
          msg("MySQL err: PHP MySQL extension not found.",-1,__LINE__,__FILE__);
        $this->success = false;
        return;
      }

      global $USERINFO;

      $this->cando['addUser']      = false;
      $this->cando['delUser']      = false;
      $this->cando['modLogin']     = false;
      $this->cando['modGroups']    = $this->cando['modLogin'];

      $this->cando['getUsers']     = true;
      $this->cando['getUserCount'] = true;

      // Try to log user in using Drupal's session cookie
      $sesscookie = false;
      $cookies = $_COOKIE;
      foreach($cookies as $cookie => $value) {
        // Find a likely Drupal cookie
        if(substr($cookie, 0, 4) == 'SESS' && strlen($cookie) == 36) {
          $sesscookie = $value;
        }

        // Now find the session in the Drupal database
        if($this->_openDB()) {
          $sql = $conf['SQLFindSession'];
          $sql = str_replace('%{sessioncookie}', $sesscookie, $sql);
          $result = $this->_queryDB($sql);

          if($result !== false) {
            if($result[0]['name']) {
              $uid = $result[0]['uid'];

              $USERINFO['name'] = $result[0]['name'];
              $USERINFO['mail'] = $result[0]['name'];
              $USERINFO['pass'] = '';
              $USERINFO['grps'] = array();

              // Now do groups
//            $sql = "SELECT r.name FROM users_roles u INNER JOIN
//                    role r WHERE u.uid='%{uid}' && u.rid=r.rid";
              $sql = $conf['SQLFindRoles'];
              $sql = str_replace('%{uid}', $uid, $sql);

              $result = $this->_queryDB($sql);

              if($result !== false) {
                foreach($result as $key => $val)
                  foreach($val as $k => $v)
                    $USERINFO['grps'][] = $v;
              }

              // Now set up session variables
              $_SERVER['REMOTE_USER'] = $result[0]['name'];
              $_SESSION[DOKU_COOKIE]['auth']['user'] = $USERINFO['name'];
              $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid();
              $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
              break;
            } else {
               // Could not find session data. Ignore cookie.
              continue;
            }
          }
          $this->_closeDB();
        } else {
          msg("Database Connection Failed. Please check your configuration.",-1,__LINE__,__FILE__);
          $this->success = false;
        }
      }
        // If DOKU_COOKIE session is ok, pass to trustExternal
        if($_SESSION[DOKU_COOKIE]['auth']['user'] != '') {
          $this->cando['external'] = true;
        }
    }

    function trustExternal() {
      return true;
    }

    /**
     * Find a pre-hashed password in the Drupal database.
     * Requires a database connection to already be open.
     *
     * @params  $user  Username for which to find the hash
     *
     * @return  Mixed  Hash of the password given, or false
     *
     * @author  Alex Shepherd  <n00bATNOSPAMn00bsys0p.co.uk>
     **/
    function _findPWHash($user)
    {
      if ($this->dbcon) {
        //$sql = "SELECT pass from users where name='%{user}'";
        $sql = $this->cnf['SQLFindPWHash'];
        $sql = str_replace('%{user}', $this->_escape($user), $sql);
        $result = $this->_queryDB($sql);
        if($result) {
          $hash = $result[0]['pass'];
          return $hash;
        } else {
          return false;
        }
      } else {
        return false;
      }
    }

    /**
     * Hash a password for Drupal, by using Drupal's password.inc
     * Set the relative location of your Drupal path, by setting
     * this->cnf['DrupalLocation'] in your configuration file.
     *
     * @params  $password  Plaintext password
     * @params  $hashedpw  Pre-hashed password from the Drupal DB
     *
     * @return  String     The hash of the password/pre-hash given
     *
     * @author  Alex Shepherd <n00bATNOSPAMn00bsys0p.co.uk>
     **/
    function _hashPW($password, $hashedpw)
    {
      $drupalroot = $this->cnf['DrupalRoot'];
      require_once($drupalroot.'includes/password.inc');
      if(!function_exists(_password_crypt)) {
        msg("Drupal installation not found. Please check your configuration",-1,__LINE__,__FILE__);
        $this->success = false;
      }
      $hash = _password_crypt('sha512', $password, $hashedpw);
      return $hash;
    }

    /**
     * Validate whether a user exists in the Drupal database
     * Requires DB Connection to be open already.
     *
     * @params  $user  User to validate within database
     *
     * @return  bool   True if user exists
     *
     * @author  Alex Shepherd <n00bATNOSPAMn00bsys0p.co.uk>
     **/
    function _validateUser($user)
    {
      if ($this->dbcon) {
        //$sql = "SELECT name from users where name='%{user}'";
        $sql = $this->cnf['SQLValidateUser'];
        $sql = str_replace('%{user}', $this->_escape($user), $sql);
        $result = $this->_queryDB($sql);

        if($result) {
          if($result[0]['name'] == $user)
            return true;
          else
            return false;
        } else {
          return false;
        }
      } else {
        msg("Database Connection Failed. Please check your configuration.",-1,__LINE__,__FILE__);
        return false;
      }
    }

    /**
     * Checks if the given user exists and the given plaintext
     * password is correct.
     *
     * @param   $user  User for whom to check the password
     * @param   $pass  Plaintext password to check for $user
     * @return  bool
     *
     * @author  Alex Shepherd <n00bATNOSPAMn00bsys0p.co.uk>
     **/
    function checkPass($user,$pass){
      $rc = false;
      if($this->_openDB()) {
        if(!$this->_validateUser($user)) {
          // User not found in database
          $rc = false;
        }
        $remotehash = $this->_findPWHash($user);
        $localhash = $this->_hashPW($pass, $remotehash);

        $rc = $remotehash == $localhash;

        if(!$remotehash || !$localhash) {
          // Hashes do not match. Password is wrong.
          $rc = false;
        }

        $this->_closeDB();
      } else {
        // Failed to open database
        $rc = false;
      }
      return $rc;
    }

}
