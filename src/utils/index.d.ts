import Q = require("q");

export class ObjectEncryptor {
    key: Buffer;
    constructor(key: Buffer);
    encrypt(object: Object): Q.Promise<Buffer>;
    decrypt<T>(data: Buffer): Q.Promise<T>;
}

export class Event {
    callbacks: Function[];
    add(callback: Function): void;
    remove(callback: Function): void;
    clear(): void;
    trigger(...args: any[]): void;
}

export type LazyMapGetter = (key: string, lazyMap: LazyMap) => any;

export class LazyMap {
    constructor(valueGetter?: LazyMapGetter);
    get<T>(key: string): T;
}
