var browserify = require('browserify');
var gulp = require('gulp');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');
var uglify = require('gulp-uglify');
var sourcemaps = require('gulp-sourcemaps');
var connect = require('gulp-connect');
var gutil      = require('gulp-util');
var watchify = require('watchify');
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

gulp.task('jsCrypto', bundlePrivmxCrypto);

browserifyPrivmxCrypto.on('update', bundlePrivmxCrypto);
browserifyPrivmxCrypto.on('log', gutil.log);
browserifyPrivmxCrypto.on('error', gutil.log);;

gulp.task('web', function(){
    connect.server({
        name: 'Demo',
        root: ['demo'],
        port: 8123,
        livereload: true
    });
})

gulp.task('serve', [], function(){
    runSequence('jsCrypto', 'web');
    
});

gulp.task('default', ['jsCrypto']);
