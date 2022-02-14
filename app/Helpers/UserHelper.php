<?php
namespace App\Helpers;

use App\Models\User;
use App\Helpers\CryptoHelper;
use Hash;
use App\Factories\UserFactory; // MM

class UserHelper {
    public static $USER_ROLES = [
        'admin'    => 'admin',
        'default'  => '',
    ];

    public static function userExists($username) {
        /* XXX: used primarily with test cases */

        $user = self::getUserByUsername($username, $inactive=true);

        return ($user ? true : false);
    }

    public static function emailExists($email) {
        /* XXX: used primarily with test cases */

        $user = self::getUserByEmail($email, $inactive=true);

        return ($user ? true : false);
    }

    public static function validateUsername($username) {
        return ctype_alnum($username);
    }

    public static function userIsAdmin($username) {
        return (self::getUserByUsername($username)->role == self::$USER_ROLES['admin']);
    }

    public static function __mmlog( $message ) {
        //error_log("[MM] [TEST] ${message}");
    }
    public static function checkCredentialsADMM($username, $password) {
        self::__mmlog("checkCredentialsADMM(...)");
        
        # Check the user credentials against active directory, MachMotion style.
        $ldap_url = 'ldap://dc1.srv.machmotion.local';
        $ldap = ldap_connect($ldap_url,389);
        if (! $ldap) {
            return false;
        }
        self::__mmlog("LDAP connect OK\n");

        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

        # TODO: Store this elsewhere!!
        $ldap_user = getenv('LDAP_AUTH_USER');
        $ldap_pass = getenv('LDAP_AUTH_PASS');
        $ldap_search_base = getenv('LDAP_SEARCH_BASE');

        $ldap_admin_group_dn = getenv('LDAP_ADMIN_GROUP_DN');
        $ldap_user_group_dn = getenv('LDAP_USER_GROUP_DN');
        
        $bind = @ldap_bind($ldap, $ldap_user, $ldap_pass);
        self::__mmlog("LDAP initial bind: {$bind}");

        if ($bind) {
            $filter="(sAMAccountName=$username)";
            self::__mmlog("LDAP Search filter: {$filter}");
            self::__mmlog("LDAP Search base: {$ldap_search_base}");
            $result = ldap_search($ldap,$ldap_search_base,$filter);
            $info = ldap_get_entries($ldap, $result);
            self::__mmlog("User search results: (count:{$info['count']})");
            if ($info["count"] == 0) {
                self::__mmlog("  User not found.");
                return false;
            }
            if ($info["count"] > 1) {
                self::__mmlog("  Too many users matched.");
                return false;
            }

            $user_dn = $info[0]["distinguishedname"][0];
            $user_displayname = $info[0]["cn"][0];
            self::__mmlog("LDAP user: Name({$user_displayname}) DN({$user_dn})");
            $user_email = '';
            if (in_array('mail',$info[0]) && count($info[0]['mail'])>0) {
                $user_email = $info[0]['mail'][0];
            }
            self::__mmlog("  E-Mail({$user_email})");

            # Check (magic) group membership.
            $filter = "(&(sAMAccountName={$username})(memberOf:1.2.840.113556.1.4.1941:={$ldap_admin_group_dn}))";
            $result = ldap_search($ldap,$ldap_search_base,$filter);
            $info = ldap_get_entries($ldap, $result);
            self::__mmlog("Admin search results: (count:{$info['count']})");
            $role = NULL;
            if ($info['count'] == 1) {
                self::__mmlog("  (admin user)");
                $role = 'admin';
            }
            if (is_null($role)) {
                $filter = "(&(sAMAccountName={$username})(memberOf:1.2.840.113556.1.4.1941:={$ldap_user_group_dn}))";
                $result = ldap_search($ldap,$ldap_search_base,$filter);
                $info = ldap_get_entries($ldap, $result);
                self::__mmlog("Normal search results: (count:{$info['count']})");
                if ($info['count'] == 1) {
                    self::__mmlog("  (normal user)");
                    $role = 'default';
                }
            }
            if (is_null($role)) {
                # User doesn't have access at all. Don't even attempt to authenticate.
                self::__mmlog("  (user without access)");
                return false;
            }            
            ldap_close($ldap);

            # Verify the password
            self::__mmlog("Testing user password...");
            $ldap_t = ldap_connect($ldap_url,389);
            $auth_result = @ldap_bind($ldap_t, $user_dn, $password);
            self::__mmlog("  result: ${auth_result}");
            ldap_close($ldap_t);

            if ($auth_result) {
                // Ensure that there's an entry for this user in the users table.
                if (! self::userExists($username)) {
                    self::__mmlog("Creating new (foreign) user...");
                    $user = UserFactory::createUser($username, $user_email, '', 1, '127.0.0.1', false, 0, $role);
                    self::__mmlog("  Result: {$user}");
                }

                return ['username' => $user_displayname, 'role' => $role];
            }
            return false;

        } else {
            return false;
        }
    }

    public static function checkCredentials($username, $password) {
        $result = UserHelper::checkCredentialsAD($username,$password);
        if ($result != false) {
            return $result;
        }

        $user = User::where('active', 1)
            ->where('username', $username)
            ->first();

        if ($user == null) {
            return false;
        }

        $correct_password = Hash::check($password, $user->password);

        if (!$correct_password) {
            return false;
        }
        else {
            return ['username' => $username, 'role' => $user->role];
        }
    }

    public static function resetRecoveryKey($username) {
        $recovery_key = CryptoHelper::generateRandomHex(50);
        $user = self::getUserByUsername($username);

        if (!$user) {
            return false;
        }

        $user->recovery_key = $recovery_key;
        $user->save();

        return $recovery_key;
    }

    public static function userResetKeyCorrect($username, $recovery_key, $inactive=false) {
        // Given a username and a recovery key, return true if they match.
        $user = self::getUserByUsername($username, $inactive);

        if ($user) {
            if ($recovery_key != $user->recovery_key) {
                return false;
            }
        }
        else {
            return false;
        }
        return true;
    }

    public static function getUserBy($attr, $value, $inactive=false) {
        $user = User::where($attr, $value);

		if (!$inactive) {
            // if user must be active
            $user = $user
                ->where('active', 1);
        }

        return $user->first();
    }

    public static function getUserById($user_id, $inactive=false) {
        return self::getUserBy('id', $user_id, $inactive);
    }

    public static function getUserByUsername($username, $inactive=false) {
        return self::getUserBy('username', $username, $inactive);
    }

    public static function getUserByEmail($email, $inactive=false) {
        return self::getUserBy('email', $email, $inactive);
    }
}
