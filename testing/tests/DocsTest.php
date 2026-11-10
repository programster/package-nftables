<?php

/*
 * Runs the examples in docs/ and the README, and checks the nft listings they show against real nft, so the docs can't
 * drift from what the code does (see DocsExampleRunner). Without nft (or unprivileged user namespaces), the examples
 * still run, but the listings aren't checked. These are run by testing/main.php, which provides $smoke and $dir.
 */

use Programster\Nftables\Testing\DocsExampleRunner;
use Programster\Nftables\Testing\NftNamespace;
use Programster\Nftables\Testing\SmokeTestRunner;

/** @var SmokeTestRunner $smoke */
/** @var string $dir - a temporary directory for the tests to use, which is deleted afterwards. */

$repoDir = dirname(__DIR__, 2);
$runner = new DocsExampleRunner($repoDir, $dir);

try
{
    NftNamespace::create($dir);
    $checkWithNft = true;
}
catch (RuntimeException $e)
{
    $checkWithNft = false;
    $smoke->skip("checking the docs' nft listings against nft", $e->getMessage());
}

$documents = [$repoDir . "/README.md", ...glob($repoDir . "/docs/*.md")];

foreach ($documents as $document)
{
    $testDocument = function () use ($runner, $document, $checkWithNft) : void {
        $runner->run($document, $checkWithNft);
    };

    $smoke->run("Docs: the examples in " . basename($document) . " work", $testDocument);
}
