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

class ArrayAuthenticator implements AuthenticatorInterface {

    public $options;
    
    public function getError() {
        return new \SlimPower\Authentication\Error();
    }

    public function __construct($options = null) {

        /* Default options. */
        $this->options = array(
            "users" => array()
        );

        if ($options) {
            $this->options = array_merge($this->options, (array) $options);
        }
    }

    public function __invoke(array $arguments) {
        $user = $arguments["user"];
        $password = $arguments["password"];
        return isset($this->options["users"][$user]) && $this->options["users"][$user] === $password;
    }

}
