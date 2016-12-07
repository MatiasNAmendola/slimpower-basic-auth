<?php

/*
 * This file is part of Slim HTTP Basic Authentication middleware
 *
 * Copyright (c) 2013-2015 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-basic-auth
 *
 */

namespace SlimPower\BasicAuth\HttpBasicAuthentication;

class RequestPathRule implements RuleInterface
{
    protected $options = array(
        "path" => array("/"),
        "passthrough" => array()
    );

    public function __construct($options = array())
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * Invoke
     * @param \SlimPower\Slim\Slim $app SlimPower instance
     * @return boolean
     */
    public function __invoke(\SlimPower\Slim\Slim $app)
    {
        $uri = $app->request->getResourceUri();

        /* If request path is matches passthrough should not authenticate. */
        foreach ((array)$this->options["passthrough"] as $passthrough) {
            $passthrough = rtrim($passthrough, "/");
            if (!!preg_match("@^{$passthrough}(/.*)?$@", $uri)) {
                return false;
            }
        }

        /* Otherwise check if path matches and we should authenticate. */
        foreach ((array)$this->options["path"] as $path) {
            $path = rtrim($path, "/");
            if (!!preg_match("@^{$path}(/.*)?$@", $uri)) {
                return true;
            }
        }
        
        return false;
    }
}
