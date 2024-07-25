<?php

namespace Programster\Nftables\Exceptions;
class ExceptionConnectionStateRequired extends \Exception
{
    public function __construct()
    {
        parent::__construct("You must provide at least one connection state.");
    }
}