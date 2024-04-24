var browserify = require('browserify');
var gulp = require('gulp');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');
var terser = require('gulp-terser');
var sourcemaps = require('gulp-sourcemaps');
var connect = require('gulp-connect');
var log      = require('fancy-log');
var watchify = require('watchify');
var minimist = require('minimist');
var through = require('through2');

var env = minimist(process.argv.slice(2));

var config = {
    production: !!env.production,
    debug: !!env.debug,
    watch: !!env.watch
};

function noop() {
    return through.obj();
}

var plugins = [];

if(config.watch) {
    plugins.push(watchify);
    log("plugins:",plugins);
}

var browserifyPrivmxCrypto = browserify({
    builtins: ["buffer", "crypto", "_process", "assert", "stream", "events", "util", "string_decoder"],
    insertGlobals : true,
    debug: config.debug,
    cache: {},
    packageCache: {},
    plugin: plugins
});

function bundlePrivmxCrypto(){
    log("bundling...");

    return browserifyPrivmxCrypto
        .require('timers-browserify', { expose: 'timers' })
        .require('q', {expose: 'q'})
        .add('./src/crypto/webworker/Listener.js')
        .require('./src/ecc/index.js', {expose: 'ecc'})
        .require('buffer', {expose: 'buffer'})
        .require('./src/index.js', {expose: 'privmx-crypto'})
        .transform("babelify", {presets: [["@babel/preset-env", {"targets": {"chrome": "60"}}]]})
        .bundle()
        .pipe(source('privmx-crypto.js'))
        .pipe(buffer())
        .pipe(sourcemaps.init({loadMaps: true}))
        .pipe(config.production ? terser({ mangle: {reserved: ['Buffer']}}) : noop())
        .on('error', log)
        .pipe(sourcemaps.write("./"))
        .pipe(gulp.dest('./build'))
}

gulp.task('jsCrypto', bundlePrivmxCrypto);

browserifyPrivmxCrypto.on('update', bundlePrivmxCrypto);
browserifyPrivmxCrypto.on('log', log);
browserifyPrivmxCrypto.on('error', log);;

gulp.task('web', function(){
    connect.server({
        name: 'Demo',
        root: ['demo'],
        port: 8123,
        livereload: true
    });
})

gulp.task('serve', gulp.series('jsCrypto', 'web'));

gulp.task('default', gulp.series('jsCrypto'));
