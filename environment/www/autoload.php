<?php
// POP gadget classes for PoC demonstration.
// In real-world exploitation these would be classes already present in the
// target application (e.g. Monolog\Handler\SyslogUdpHandler, Laravel's
// PendingBroadcast, Guzzle\Cookie\FileCookieJar, Symfony\Component\...).

class Logger {
    public $handler;

    public function __destruct() {
        if ($this->handler) {
            $this->handler->close();
        }
    }
}

class CommandHandler {
    public $command;
    public $output_file;

    public function close() {
        if ($this->command) {
            $output = shell_exec($this->command . ' 2>&1');
            if ($this->output_file) {
                file_put_contents($this->output_file, $output);
            }
        }
    }
}
