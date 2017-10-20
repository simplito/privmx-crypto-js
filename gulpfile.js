var browserify = require('browserify');
var gulp = require('gulp');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');
var uglify = require('gulp-uglify');
var sourcemaps = require('gulp-sourcemaps');
var connect = require('gulp-connect');
var gutil      = require('gulp-util');
var watchify = require('watchify');
var vfs = require('vinyl-fs');
var runSequence = require('run-sequence');

var config = {
    production: !!gutil.env.production,
    debug: !!gutil.env.debug,
    watch: !!gutil.env.watch
};

var plugins = [];

if(config.watch) {
    plugins.push(watchify);
    gutil.log("plugins:",plugins);
}

var browserifyPrivmxCrypto = browserify({
    builtins: ["buffer", "crypto", "_process", "assert", "stream", "events", "util", "string_decoder"],
    insertGlobals : true,
    debug: config.debug,
    cache: {},
    packageCache: {},
    plugin: plugins
});

var browserifyWorker = browserify({
    builtins: ["buffer", "crypto", "_process", "assert", "stream", "events", "util", "string_decoder"],
    insertGlobals : true,
    debug: config.debug,
    cache: {},
    packageCache: {},
    plugin: plugins
});

function bundleWorker(){
    gutil.log("bundling...");

    return browserifyWorker
        .require('q', {expose: 'q'})
        .add('./src/crypto/webworker/Listener.js')
        .ignore('./src/rsa/rsa-subtle.js')
        .ignore('./src/crypto/CryptoSubtle.js')
        .transform("babelify", {presets: ["es2015"]})
        .bundle()
        .pipe(source('PrivmxWorker.js'))
        .pipe(buffer())
        .pipe(sourcemaps.init({loadMaps: true}))
        .pipe(config.production ? uglify() : gutil.noop())
        .on('error', gutil.log)
        .pipe(sourcemaps.write("./"))
        .pipe(gulp.dest('./build'))
}

function bundlePrivmxCrypto(){
    gutil.log("bundling...");

    return browserifyPrivmxCrypto
        .require('q', {expose: 'q'})
        .add('./src/crypto/webworker/Listener.js')
        .require('./src/ecc/index.js', {expose: 'ecc'})
        .require('buffer', {expose: 'buffer'})
        .require('./src/index.js', {expose: 'privmx-crypto'})
        .transform("babelify", {presets: ["es2015"]})
        .bundle()
        .pipe(source('privmx-crypto.js'))
        .pipe(buffer())
        .pipe(sourcemaps.init({loadMaps: true}))
        .pipe(config.production ? uglify({ mangle: {except: ['Buffer']}}) : gutil.noop())
        .on('error', gutil.log)
        .pipe(sourcemaps.write("./"))
        .pipe(gulp.dest('./build'))
}

gulp.task('jsWorker', bundleWorker);
gulp.task('jsCrypto', bundlePrivmxCrypto);

browserifyPrivmxCrypto.on('update', bundlePrivmxCrypto);
browserifyPrivmxCrypto.on('log', gutil.log);
browserifyPrivmxCrypto.on('error', gutil.log);;

browserifyWorker.on('update', bundleWorker);
browserifyWorker.on('log', gutil.log);
browserifyWorker.on('error', gutil.log);;

gulp.task('createLinkWorker', function(){
    return vfs.src(['./build/PrivmxWorker.js', './build/PrivmxWorker.js.map'], {followSymlinks: false, read: false})
        .pipe(vfs.symlink('./demo'));
});

gulp.task('createLinkCrypto', function(){
    return vfs.src(['./build/privmx-crypto.js', './build/privmx-crypto.js.map'], {followSymlinks: false, read: false})
        .pipe(vfs.symlink('./demo'));
});

gulp.task('web', function(){
    connect.server({
        name: 'Demo',
        root: ['demo'],
        port: 8123,
        livereload: true
    });
})

gulp.task('serve', [], function(){
    runSequence(['jsWorker', 'jsCrypto'], ['createLinkWorker', 'createLinkCrypto'], 'web');
    
});

gulp.task('default', ['jsWorker', 'jsCrypto']);
