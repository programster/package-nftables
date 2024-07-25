<?php

namespace Programster\Nftables\Exceptions;
class ExceptionPortRequired extends \Exception
{
    public function __construct()
    {
        parent::__construct("You must provide at least one port.");
    }
}