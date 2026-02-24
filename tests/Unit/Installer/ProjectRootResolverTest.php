<?php

declare(strict_types=1);

use stimmt\craft\Mcp\installer\ProjectRootResolver;

beforeEach(function () {
    $this->tempDir = sys_get_temp_dir() . '/craft-mcp-resolver-tests-' . uniqid();
    mkdir($this->tempDir, 0755, true);
});

afterEach(function () {
    // Clean up temp directory tree
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($this->tempDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($this->tempDir);
});

describe('ProjectRootResolver::resolve()', function () {
    it('returns craft root when no markers are found', function () {
        $craftRoot = $this->tempDir . '/project/backend';
        mkdir($craftRoot, 0755, true);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->resolve())->toBe($craftRoot);
    });

    it('detects .ddev marker in parent directory', function () {
        $projectRoot = $this->tempDir . '/project';
        $craftRoot = $projectRoot . '/backend';
        mkdir($craftRoot, 0755, true);
        mkdir($projectRoot . '/.ddev', 0755);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->resolve())->toBe($projectRoot);
    });

    it('detects .git marker in parent directory', function () {
        $projectRoot = $this->tempDir . '/project';
        $craftRoot = $projectRoot . '/backend';
        mkdir($craftRoot, 0755, true);
        mkdir($projectRoot . '/.git', 0755);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->resolve())->toBe($projectRoot);
    });

    it('prefers closest parent with marker', function () {
        $outerRoot = $this->tempDir . '/outer';
        $innerRoot = $outerRoot . '/inner';
        $craftRoot = $innerRoot . '/backend';
        mkdir($craftRoot, 0755, true);
        mkdir($outerRoot . '/.git', 0755);
        mkdir($innerRoot . '/.ddev', 0755);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->resolve())->toBe($innerRoot);
    });

    it('detects marker two levels up', function () {
        $projectRoot = $this->tempDir . '/project';
        $craftRoot = $projectRoot . '/apps/backend';
        mkdir($craftRoot, 0755, true);
        mkdir($projectRoot . '/.git', 0755);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->resolve())->toBe($projectRoot);
    });

    it('does not search beyond max depth', function () {
        $projectRoot = $this->tempDir . '/a';
        $craftRoot = $projectRoot . '/b/c/d/e';
        mkdir($craftRoot, 0755, true);
        mkdir($projectRoot . '/.git', 0755);

        $resolver = new ProjectRootResolver($craftRoot);

        // 4 levels deep — beyond max depth of 3
        expect($resolver->resolve())->toBe($craftRoot);
    });

    it('returns craft root when marker is at craft root itself', function () {
        $craftRoot = $this->tempDir . '/project';
        mkdir($craftRoot, 0755, true);
        mkdir($craftRoot . '/.ddev', 0755);

        $resolver = new ProjectRootResolver($craftRoot);

        // .ddev is AT the craft root, not a parent — resolve only checks parents
        expect($resolver->resolve())->toBe($craftRoot);
    });
});

describe('ProjectRootResolver::getSubdirectory()', function () {
    it('returns null when project root equals craft root', function () {
        $craftRoot = $this->tempDir . '/project';
        mkdir($craftRoot, 0755, true);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->getSubdirectory($craftRoot))->toBeNull();
    });

    it('returns relative subdirectory path', function () {
        $projectRoot = $this->tempDir . '/project';
        $craftRoot = $projectRoot . '/backend';
        mkdir($craftRoot, 0755, true);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->getSubdirectory($projectRoot))->toBe('backend');
    });

    it('returns nested subdirectory path', function () {
        $projectRoot = $this->tempDir . '/project';
        $craftRoot = $projectRoot . '/apps/backend';
        mkdir($craftRoot, 0755, true);

        $resolver = new ProjectRootResolver($craftRoot);

        expect($resolver->getSubdirectory($projectRoot))->toBe('apps/backend');
    });
});
