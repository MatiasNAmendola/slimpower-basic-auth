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

use SlimPower\Authentication\Abstracts\LoginAuthMiddleware;

class HttpBasicAuthentication extends LoginAuthMiddleware {

    public function callError() {
        $this->app->response->header("WWW-Authenticate", sprintf('Basic realm="%s"', $this->options["realm"]));
        parent::callError();
    }

    /**
     * Fetch data
     *
     * @return array|false Data or false if not found.
     */
    protected function fetchData() {
        $environment = $this->app->environment;
        $user = false;
        $password = false;

        /* If using PHP in CGI mode. */
        if (isset($_SERVER[$this->options["environment"]])) {
            $matches = null;

            if (preg_match("/Basic\s+(.*)$/i", $_SERVER[$this->options["environment"]], $matches)) {
                list($user, $password) = explode(":", base64_decode($matches[1]));
            }
        } else {
            $user = $environment["PHP_AUTH_USER"];
            $password = $environment["PHP_AUTH_PW"];
        }

        if (empty($user) || empty($password)) {
            return false;
        }

        $params = array(parent::KEY_USERNAME => $user, parent::KEY_PASSWORD => $password);
        return $params;
    }

}
