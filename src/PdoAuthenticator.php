<?php

/**
 * This file is part of Slim HTTP Basic Authentication middleware
 *
 * @category   Authentication
 * @package    SlimPower
 * @subpackage HttpBasicAuthentication
 * @author     Matias Nahuel Améndola <soporte.esolutions@gmail.com>
 * @link       https://github.com/MatiasNAmendola/slimpower-basic-auth
 * @license    https://github.com/MatiasNAmendola/slimpower-basic-auth/blob/master/LICENSE.md
 * @since      0.0.1
 * 
 * MIT LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace SlimPower\HttpBasicAuthentication;

use SlimPower\Authentication\Interfaces\AuthenticatorInterface;

class PdoAuthenticator implements AuthenticatorInterface {

    private $options;
    private $data = array();
    private $error = null;

    public function getData() {
        return $this->data;
    }

    public function getError() {
        return $this->error;
    }

    public function __construct(array $options = array()) {

        /* Default options. */
        $this->options = array(
            "table" => "users",
            "user" => "user",
            "hash" => "hash",
            "show" => array() /* fields to show */
        );

        if ($options) {
            $this->options = array_merge($this->options, $options);
        }
    }

    public function __invoke(array $arguments) {
        $user = $arguments["user"];
        $password = $arguments["password"];

        $driver = $this->options["pdo"]->getAttribute(\PDO::ATTR_DRIVER_NAME);

        $sql = $this->sql();

        $statement = $this->options["pdo"]->prepare($sql);
        $statement->execute(array($user));

        $success = false;

        if ($user = $statement->fetch(\PDO::FETCH_ASSOC)) {
            $success = password_verify($password, $user[$this->options["hash"]]);
        }

        if (!$success) {
            $this->error = new \SlimPower\Authentication\Error();
        } else {
            $this->data = array();

            foreach ($this->options["show"] as $fieldname) {
                if (array_key_exists($fieldname, $user)) {
                    $this->data[$fieldname] = $user[$fieldname];
                }
            }
        }

        return $success;
    }

    public function sql() {
        $driver = $this->options["pdo"]->getAttribute(\PDO::ATTR_DRIVER_NAME);

        /* Workaround to test without sqlsrv with Travis */
        if (defined("__PHPUNIT_ATTR_DRIVER_NAME__")) {
            $driver = __PHPUNIT_ATTR_DRIVER_NAME__;
        }

        if ("sqlsrv" === $driver) {
            $sql = "SELECT TOP 1 *
                 FROM {$this->options['table']}
                 WHERE {$this->options['user']} = ?";
        } else {
            $sql = "SELECT *
                 FROM {$this->options['table']}
                 WHERE {$this->options['user']} = ?
                 LIMIT 1";
        }

        return preg_replace("!\s+!", " ", $sql);
    }

}
