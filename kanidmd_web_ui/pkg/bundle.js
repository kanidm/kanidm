(function () {
    'use strict';

    let wasm;

    const heap = new Array(32).fill(undefined);

    heap.push(undefined, null, true, false);

    function getObject(idx) { return heap[idx]; }

    let WASM_VECTOR_LEN = 0;

    let cachegetUint8Memory0 = null;
    function getUint8Memory0() {
        if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
            cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
        }
        return cachegetUint8Memory0;
    }

    let cachedTextEncoder = new TextEncoder('utf-8');

    const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
        ? function (arg, view) {
        return cachedTextEncoder.encodeInto(arg, view);
    }
        : function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    });

    function passStringToWasm0(arg, malloc, realloc) {

        if (typeof(arg) !== 'string') throw new Error('expected a string argument');

        if (realloc === undefined) {
            const buf = cachedTextEncoder.encode(arg);
            const ptr = malloc(buf.length);
            getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
            WASM_VECTOR_LEN = buf.length;
            return ptr;
        }

        let len = arg.length;
        let ptr = malloc(len);

        const mem = getUint8Memory0();

        let offset = 0;

        for (; offset < len; offset++) {
            const code = arg.charCodeAt(offset);
            if (code > 0x7F) break;
            mem[ptr + offset] = code;
        }

        if (offset !== len) {
            if (offset !== 0) {
                arg = arg.slice(offset);
            }
            ptr = realloc(ptr, len, len = offset + arg.length * 3);
            const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
            const ret = encodeString(arg, view);
            if (ret.read !== arg.length) throw new Error('failed to pass whole string');
            offset += ret.written;
        }

        WASM_VECTOR_LEN = offset;
        return ptr;
    }

    let cachegetInt32Memory0 = null;
    function getInt32Memory0() {
        if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
            cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
        }
        return cachegetInt32Memory0;
    }

    let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

    cachedTextDecoder.decode();

    function getStringFromWasm0(ptr, len) {
        return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
    }

    let heap_next = heap.length;

    function addHeapObject(obj) {
        if (heap_next === heap.length) heap.push(heap.length + 1);
        const idx = heap_next;
        heap_next = heap[idx];

        if (typeof(heap_next) !== 'number') throw new Error('corrupt heap');

        heap[idx] = obj;
        return idx;
    }

    function isLikeNone(x) {
        return x === undefined || x === null;
    }

    function _assertBoolean(n) {
        if (typeof(n) !== 'boolean') {
            throw new Error('expected a boolean argument');
        }
    }

    function _assertNum(n) {
        if (typeof(n) !== 'number') throw new Error('expected a number argument');
    }

    let cachegetFloat64Memory0 = null;
    function getFloat64Memory0() {
        if (cachegetFloat64Memory0 === null || cachegetFloat64Memory0.buffer !== wasm.memory.buffer) {
            cachegetFloat64Memory0 = new Float64Array(wasm.memory.buffer);
        }
        return cachegetFloat64Memory0;
    }

    function dropObject(idx) {
        if (idx < 36) return;
        heap[idx] = heap_next;
        heap_next = idx;
    }

    function takeObject(idx) {
        const ret = getObject(idx);
        dropObject(idx);
        return ret;
    }

    function debugString(val) {
        // primitive types
        const type = typeof val;
        if (type == 'number' || type == 'boolean' || val == null) {
            return  `${val}`;
        }
        if (type == 'string') {
            return `"${val}"`;
        }
        if (type == 'symbol') {
            const description = val.description;
            if (description == null) {
                return 'Symbol';
            } else {
                return `Symbol(${description})`;
            }
        }
        if (type == 'function') {
            const name = val.name;
            if (typeof name == 'string' && name.length > 0) {
                return `Function(${name})`;
            } else {
                return 'Function';
            }
        }
        // objects
        if (Array.isArray(val)) {
            const length = val.length;
            let debug = '[';
            if (length > 0) {
                debug += debugString(val[0]);
            }
            for(let i = 1; i < length; i++) {
                debug += ', ' + debugString(val[i]);
            }
            debug += ']';
            return debug;
        }
        // Test for built-in
        const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
        let className;
        if (builtInMatches.length > 1) {
            className = builtInMatches[1];
        } else {
            // Failed to match the standard '[object ClassName]'
            return toString.call(val);
        }
        if (className == 'Object') {
            // we're a user defined class or Object
            // JSON.stringify avoids problems with cycles, and is generally much
            // easier than looping through ownProperties of `val`.
            try {
                return 'Object(' + JSON.stringify(val) + ')';
            } catch (_) {
                return 'Object';
            }
        }
        // errors
        if (val instanceof Error) {
            return `${val.name}: ${val.message}\n${val.stack}`;
        }
        // TODO we could test for more things here, like `Set`s and `Map`s.
        return className;
    }

    function makeClosure(arg0, arg1, dtor, f) {
        const state = { a: arg0, b: arg1, cnt: 1, dtor };
        const real = (...args) => {
            // First up with a closure we increment the internal reference
            // count. This ensures that the Rust closure environment won't
            // be deallocated while we're invoking it.
            state.cnt++;
            try {
                return f(state.a, state.b, ...args);
            } finally {
                if (--state.cnt === 0) {
                    wasm.__wbindgen_export_2.get(state.dtor)(state.a, state.b);
                    state.a = 0;

                }
            }
        };
        real.original = state;

        return real;
    }

    function logError(f, args) {
        try {
            return f.apply(this, args);
        } catch (e) {
            let error = (function () {
                try {
                    return e instanceof Error ? `${e.message}\n\nStack:\n${e.stack}` : e.toString();
                } catch(_) {
                    return "<failed to stringify thrown value>";
                }
            }());
            console.error("wasm-bindgen: imported JS function that was not marked as `catch` threw an error:", error);
            throw e;
        }
    }
    function __wbg_adapter_32(arg0, arg1, arg2) {
        _assertNum(arg0);
        _assertNum(arg1);
        wasm._dyn_core__ops__function__Fn__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hb61ea9627cc39291(arg0, arg1, addHeapObject(arg2));
    }

    function makeMutClosure(arg0, arg1, dtor, f) {
        const state = { a: arg0, b: arg1, cnt: 1, dtor };
        const real = (...args) => {
            // First up with a closure we increment the internal reference
            // count. This ensures that the Rust closure environment won't
            // be deallocated while we're invoking it.
            state.cnt++;
            const a = state.a;
            state.a = 0;
            try {
                return f(a, state.b, ...args);
            } finally {
                if (--state.cnt === 0) {
                    wasm.__wbindgen_export_2.get(state.dtor)(a, state.b);

                } else {
                    state.a = a;
                }
            }
        };
        real.original = state;

        return real;
    }
    function __wbg_adapter_35(arg0, arg1, arg2) {
        _assertNum(arg0);
        _assertNum(arg1);
        wasm._dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hb605b3d6aec53c37(arg0, arg1, addHeapObject(arg2));
    }

    let stack_pointer = 32;

    function addBorrowedObject(obj) {
        if (stack_pointer == 1) throw new Error('out of js stack');
        heap[--stack_pointer] = obj;
        return stack_pointer;
    }
    function __wbg_adapter_38(arg0, arg1, arg2) {
        try {
            _assertNum(arg0);
            _assertNum(arg1);
            wasm._dyn_core__ops__function__FnMut___A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hb2f17c369ffdb26e(arg0, arg1, addBorrowedObject(arg2));
        } finally {
            heap[stack_pointer++] = undefined;
        }
    }

    /**
    */
    function run_app() {
        wasm.run_app();
    }

    let cachegetUint32Memory0 = null;
    function getUint32Memory0() {
        if (cachegetUint32Memory0 === null || cachegetUint32Memory0.buffer !== wasm.memory.buffer) {
            cachegetUint32Memory0 = new Uint32Array(wasm.memory.buffer);
        }
        return cachegetUint32Memory0;
    }

    function getArrayJsValueFromWasm0(ptr, len) {
        const mem = getUint32Memory0();
        const slice = mem.subarray(ptr / 4, ptr / 4 + len);
        const result = [];
        for (let i = 0; i < slice.length; i++) {
            result.push(takeObject(slice[i]));
        }
        return result;
    }

    function handleError(f, args) {
        try {
            return f.apply(this, args);
        } catch (e) {
            wasm.__wbindgen_exn_store(addHeapObject(e));
        }
    }

    async function load(module, imports) {
        if (typeof Response === 'function' && module instanceof Response) {
            if (typeof WebAssembly.instantiateStreaming === 'function') {
                try {
                    return await WebAssembly.instantiateStreaming(module, imports);

                } catch (e) {
                    if (module.headers.get('Content-Type') != 'application/wasm') {
                        console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                    } else {
                        throw e;
                    }
                }
            }

            const bytes = await module.arrayBuffer();
            return await WebAssembly.instantiate(bytes, imports);

        } else {
            const instance = await WebAssembly.instantiate(module, imports);

            if (instance instanceof WebAssembly.Instance) {
                return { instance, module };

            } else {
                return instance;
            }
        }
    }

    async function init(input) {
        if (typeof input === 'undefined') {
            input = new URL('kanidmd_web_ui_bg.wasm', (document.currentScript && document.currentScript.src || new URL('bundle.js', document.baseURI).href));
        }
        const imports = {};
        imports.wbg = {};
        imports.wbg.__wbindgen_json_serialize = function(arg0, arg1) {
            const obj = getObject(arg1);
            var ret = JSON.stringify(obj === undefined ? null : obj);
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        };
        imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
            var ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        };
        imports.wbg.__wbindgen_string_get = function(arg0, arg1) {
            const obj = getObject(arg1);
            var ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr0 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        };
        imports.wbg.__wbindgen_object_clone_ref = function(arg0) {
            var ret = getObject(arg0);
            return addHeapObject(ret);
        };
        imports.wbg.__wbindgen_json_parse = function(arg0, arg1) {
            var ret = JSON.parse(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        };
        imports.wbg.__wbindgen_is_undefined = function(arg0) {
            var ret = getObject(arg0) === undefined;
            _assertBoolean(ret);
            return ret;
        };
        imports.wbg.__wbindgen_boolean_get = function(arg0) {
            const v = getObject(arg0);
            var ret = typeof(v) === 'boolean' ? (v ? 1 : 0) : 2;
            _assertNum(ret);
            return ret;
        };
        imports.wbg.__wbindgen_number_get = function(arg0, arg1) {
            const obj = getObject(arg1);
            var ret = typeof(obj) === 'number' ? obj : undefined;
            if (!isLikeNone(ret)) {
                _assertNum(ret);
            }
            getFloat64Memory0()[arg0 / 8 + 1] = isLikeNone(ret) ? 0 : ret;
            getInt32Memory0()[arg0 / 4 + 0] = !isLikeNone(ret);
        };
        imports.wbg.__wbindgen_number_new = function(arg0) {
            var ret = arg0;
            return addHeapObject(ret);
        };
        imports.wbg.__wbindgen_object_drop_ref = function(arg0) {
            takeObject(arg0);
        };
        imports.wbg.__wbg_error_09919627ac0992f5 = function() { return logError(function (arg0, arg1) {
            try {
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(arg0, arg1);
            }
        }, arguments) };
        imports.wbg.__wbg_new_693216e109162396 = function() { return logError(function () {
            var ret = new Error();
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_stack_0ddaca5d1abfb52f = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg1).stack;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbindgen_cb_drop = function(arg0) {
            const obj = takeObject(arg0).original;
            if (obj.cnt-- == 1) {
                obj.a = 0;
                return true;
            }
            var ret = false;
            _assertBoolean(ret);
            return ret;
        };
        imports.wbg.__wbg_log_06b7ffc63a0f8bee = function() { return logError(function (arg0, arg1) {
            var v0 = getArrayJsValueFromWasm0(arg0, arg1).slice();
            wasm.__wbindgen_free(arg0, arg1 * 4);
            console.log(...v0);
        }, arguments) };
        imports.wbg.__wbg_warn_2aa0e7178e1d35f6 = function() { return logError(function (arg0, arg1) {
            var v0 = getArrayJsValueFromWasm0(arg0, arg1).slice();
            wasm.__wbindgen_free(arg0, arg1 * 4);
            console.warn(...v0);
        }, arguments) };
        imports.wbg.__wbg_instanceof_Window_c4b70662a0d2c5ec = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof Window;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_document_1c64944725c0d81d = function() { return logError(function (arg0) {
            var ret = getObject(arg0).document;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_location_f98ad02632f88c43 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).location;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_history_3ac8f1466e0c0528 = function() { return handleError(function (arg0) {
            var ret = getObject(arg0).history;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_navigator_480e592af6ad365b = function() { return logError(function (arg0) {
            var ret = getObject(arg0).navigator;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_localStorage_6775414303ab5085 = function() { return handleError(function (arg0) {
            var ret = getObject(arg0).localStorage;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_sessionStorage_91431bb083105afe = function() { return handleError(function (arg0) {
            var ret = getObject(arg0).sessionStorage;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_fetch_cfe0d1dd786e9cd4 = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg0).fetch(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_documentElement_f68af1ca898aebe4 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).documentElement;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_body_78ae4fd43b446013 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).body;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_createElement_86c152812a141a62 = function() { return handleError(function (arg0, arg1, arg2) {
            var ret = getObject(arg0).createElement(getStringFromWasm0(arg1, arg2));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_createElementNS_ae12b8681c3957a3 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            var ret = getObject(arg0).createElementNS(arg1 === 0 ? undefined : getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_createTextNode_365db3bc3d0523ab = function() { return logError(function (arg0, arg1, arg2) {
            var ret = getObject(arg0).createTextNode(getStringFromWasm0(arg1, arg2));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_getElementById_f3e94458ce77f0d0 = function() { return logError(function (arg0, arg1, arg2) {
            var ret = getObject(arg0).getElementById(getStringFromWasm0(arg1, arg2));
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_querySelector_b92a6c73bcfe671b = function() { return handleError(function (arg0, arg1, arg2) {
            var ret = getObject(arg0).querySelector(getStringFromWasm0(arg1, arg2));
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_get_398540d826c14d7c = function() { return handleError(function (arg0, arg1, arg2, arg3) {
            var ret = getObject(arg1).get(getStringFromWasm0(arg2, arg3));
            var ptr0 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_set_5357fedb30848723 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            getObject(arg0).set(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments) };
        imports.wbg.__wbg_instanceof_Response_e1b11afbefa5b563 = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof Response;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_status_6d8bb444ddc5a7b2 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).status;
            _assertNum(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_headers_5ffa990806e04cfc = function() { return logError(function (arg0) {
            var ret = getObject(arg0).headers;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_json_88cc6d5cf8f61121 = function() { return handleError(function (arg0) {
            var ret = getObject(arg0).json();
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_text_8279d34d73e43c68 = function() { return handleError(function (arg0) {
            var ret = getObject(arg0).text();
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_pathname_3570d699aa5b91aa = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg1).pathname;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_new_3f48783ae4f87f8f = function() { return handleError(function (arg0, arg1) {
            var ret = new URL(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_get_49ddec76fecb886f = function() { return handleError(function (arg0, arg1) {
            var ret = getObject(arg0).get(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_href_1194e84dd750563a = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg1).href;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_value_686b2a68422cb88d = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg1).value;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_setvalue_0a07023245efa3cc = function() { return logError(function (arg0, arg1, arg2) {
            getObject(arg0).value = getStringFromWasm0(arg1, arg2);
        }, arguments) };
        imports.wbg.__wbg_headers_4764f5445b6a6c89 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).headers;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_newwithstrandinit_9b0fa00478c37287 = function() { return handleError(function (arg0, arg1, arg2) {
            var ret = new Request(getStringFromWasm0(arg0, arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_instanceof_Event_480a3ec3d45b75a6 = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof Event;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_target_cc69dde6c2d9ec90 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).target;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_cancelBubble_f67c419013823f11 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).cancelBubble;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_preventDefault_9866c9fd51eecfb6 = function() { return logError(function (arg0) {
            getObject(arg0).preventDefault();
        }, arguments) };
        imports.wbg.__wbg_getClientExtensionResults_73fef7f1197950fb = function() { return logError(function (arg0) {
            var ret = getObject(arg0).getClientExtensionResults();
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_addEventListener_09e11fbf8b4b719b = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            getObject(arg0).addEventListener(getStringFromWasm0(arg1, arg2), getObject(arg3), getObject(arg4));
        }, arguments) };
        imports.wbg.__wbg_removeEventListener_24d5a7c12c3f3c39 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            getObject(arg0).removeEventListener(getStringFromWasm0(arg1, arg2), getObject(arg3), arg4 !== 0);
        }, arguments) };
        imports.wbg.__wbg_instanceof_HtmlInputElement_8cafe5f30dfdb6bc = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof HTMLInputElement;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_setchecked_206243371da58f6a = function() { return logError(function (arg0, arg1) {
            getObject(arg0).checked = arg1 !== 0;
        }, arguments) };
        imports.wbg.__wbg_value_0627d4b1c27534e6 = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg1).value;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_setvalue_2459f62386b6967f = function() { return logError(function (arg0, arg1, arg2) {
            getObject(arg0).value = getStringFromWasm0(arg1, arg2);
        }, arguments) };
        imports.wbg.__wbg_instanceof_Element_97d85e53f1805b82 = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof Element;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_namespaceURI_f4cd665d07463337 = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg1).namespaceURI;
            var ptr0 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_removeAttribute_eea03ed128669b8f = function() { return handleError(function (arg0, arg1, arg2) {
            getObject(arg0).removeAttribute(getStringFromWasm0(arg1, arg2));
        }, arguments) };
        imports.wbg.__wbg_setAttribute_1b533bf07966de55 = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            getObject(arg0).setAttribute(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments) };
        imports.wbg.__wbg_instanceof_HtmlElement_df66c8b4a687aa43 = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof HTMLElement;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_focus_00530e359f44fc6e = function() { return handleError(function (arg0) {
            getObject(arg0).focus();
        }, arguments) };
        imports.wbg.__wbg_instanceof_HtmlDocument_1faa18f5a2da6fb3 = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof HTMLDocument;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_cookie_becfe81fc969a9ff = function() { return handleError(function (arg0, arg1) {
            var ret = getObject(arg1).cookie;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_credentials_5339e35d156d6605 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).credentials;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_parentElement_0253a5d6c3ff0ba5 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).parentElement;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_lastChild_ca5bac177ef353f6 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).lastChild;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_setnodeValue_702374ad3d0ec3df = function() { return logError(function (arg0, arg1, arg2) {
            getObject(arg0).nodeValue = arg1 === 0 ? undefined : getStringFromWasm0(arg1, arg2);
        }, arguments) };
        imports.wbg.__wbg_appendChild_d318db34c4559916 = function() { return handleError(function (arg0, arg1) {
            var ret = getObject(arg0).appendChild(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_insertBefore_5b314357408fbec1 = function() { return handleError(function (arg0, arg1, arg2) {
            var ret = getObject(arg0).insertBefore(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_removeChild_d3ca7b53e537867e = function() { return handleError(function (arg0, arg1) {
            var ret = getObject(arg0).removeChild(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_pushState_f772e11155235e9c = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5) {
            getObject(arg0).pushState(getObject(arg1), getStringFromWasm0(arg2, arg3), arg4 === 0 ? undefined : getStringFromWasm0(arg4, arg5));
        }, arguments) };
        imports.wbg.__wbg_pathname_32da720074d17e34 = function() { return handleError(function (arg0, arg1) {
            var ret = getObject(arg1).pathname;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_search_f44353b4fdbdd216 = function() { return handleError(function (arg0, arg1) {
            var ret = getObject(arg1).search;
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_replace_fde8d9ba8c5000f9 = function() { return handleError(function (arg0, arg1, arg2) {
            getObject(arg0).replace(getStringFromWasm0(arg1, arg2));
        }, arguments) };
        imports.wbg.__wbg_getItem_77fb9d4666f3b93a = function() { return handleError(function (arg0, arg1, arg2, arg3) {
            var ret = getObject(arg1).getItem(getStringFromWasm0(arg2, arg3));
            var ptr0 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        }, arguments) };
        imports.wbg.__wbg_removeItem_e02016195a414450 = function() { return handleError(function (arg0, arg1, arg2) {
            getObject(arg0).removeItem(getStringFromWasm0(arg1, arg2));
        }, arguments) };
        imports.wbg.__wbg_setItem_b0c4561489dffecd = function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            getObject(arg0).setItem(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments) };
        imports.wbg.__wbg_new_949bbc1147195c4e = function() { return logError(function () {
            var ret = new Array();
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_push_284486ca27c6aa8b = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg0).push(getObject(arg1));
            _assertNum(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_instanceof_Error_561efcb1265706d8 = function() { return logError(function (arg0) {
            var ret = getObject(arg0) instanceof Error;
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_message_9f7d15ff97fc4102 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).message;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_name_5a42234155690dbc = function() { return logError(function (arg0) {
            var ret = getObject(arg0).name;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_toString_0ef1ea57b966aed4 = function() { return logError(function (arg0) {
            var ret = getObject(arg0).toString();
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_newnoargs_be86524d73f67598 = function() { return logError(function (arg0, arg1) {
            var ret = new Function(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_call_888d259a5fefc347 = function() { return handleError(function (arg0, arg1) {
            var ret = getObject(arg0).call(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_valueOf_99d85ac83228d11b = function() { return logError(function (arg0) {
            var ret = getObject(arg0).valueOf();
            return ret;
        }, arguments) };
        imports.wbg.__wbg_is_0f5efc7977a2c50b = function() { return logError(function (arg0, arg1) {
            var ret = Object.is(getObject(arg0), getObject(arg1));
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_new_0b83d3df67ecb33e = function() { return logError(function () {
            var ret = new Object();
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_resolve_d23068002f584f22 = function() { return logError(function (arg0) {
            var ret = Promise.resolve(getObject(arg0));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_then_2fcac196782070cc = function() { return logError(function (arg0, arg1) {
            var ret = getObject(arg0).then(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_then_8c2d62e8ae5978f7 = function() { return logError(function (arg0, arg1, arg2) {
            var ret = getObject(arg0).then(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_globalThis_3f735a5746d41fbd = function() { return handleError(function () {
            var ret = globalThis.globalThis;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_self_c6fbdfc2918d5e58 = function() { return handleError(function () {
            var ret = self.self;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_window_baec038b5ab35c54 = function() { return handleError(function () {
            var ret = window.window;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_global_1bc0b39582740e95 = function() { return handleError(function () {
            var ret = global.global;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_new_a7ce447f15ff496f = function() { return logError(function (arg0) {
            var ret = new Uint8Array(getObject(arg0));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_newwithbyteoffsetandlength_4b9b8c4e3f5adbff = function() { return logError(function (arg0, arg1, arg2) {
            var ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_length_1eb8fc608a0d4cdb = function() { return logError(function (arg0) {
            var ret = getObject(arg0).length;
            _assertNum(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbg_set_969ad0a60e51d320 = function() { return logError(function (arg0, arg1, arg2) {
            getObject(arg0).set(getObject(arg1), arg2 >>> 0);
        }, arguments) };
        imports.wbg.__wbg_buffer_397eaa4d72ee94dd = function() { return logError(function (arg0) {
            var ret = getObject(arg0).buffer;
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_get_4d0f21c2f823742e = function() { return handleError(function (arg0, arg1) {
            var ret = Reflect.get(getObject(arg0), getObject(arg1));
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbg_set_82a4e8a85e31ac42 = function() { return handleError(function (arg0, arg1, arg2) {
            var ret = Reflect.set(getObject(arg0), getObject(arg1), getObject(arg2));
            _assertBoolean(ret);
            return ret;
        }, arguments) };
        imports.wbg.__wbindgen_debug_string = function(arg0, arg1) {
            var ret = debugString(getObject(arg1));
            var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            getInt32Memory0()[arg0 / 4 + 1] = len0;
            getInt32Memory0()[arg0 / 4 + 0] = ptr0;
        };
        imports.wbg.__wbindgen_throw = function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        };
        imports.wbg.__wbindgen_rethrow = function(arg0) {
            throw takeObject(arg0);
        };
        imports.wbg.__wbindgen_memory = function() {
            var ret = wasm.memory;
            return addHeapObject(ret);
        };
        imports.wbg.__wbindgen_closure_wrapper13062 = function() { return logError(function (arg0, arg1, arg2) {
            var ret = makeClosure(arg0, arg1, 685, __wbg_adapter_32);
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbindgen_closure_wrapper14676 = function() { return logError(function (arg0, arg1, arg2) {
            var ret = makeMutClosure(arg0, arg1, 697, __wbg_adapter_35);
            return addHeapObject(ret);
        }, arguments) };
        imports.wbg.__wbindgen_closure_wrapper15087 = function() { return logError(function (arg0, arg1, arg2) {
            var ret = makeMutClosure(arg0, arg1, 730, __wbg_adapter_38);
            return addHeapObject(ret);
        }, arguments) };

        if (typeof input === 'string' || (typeof Request === 'function' && input instanceof Request) || (typeof URL === 'function' && input instanceof URL)) {
            input = fetch(input);
        }



        const { instance, module } = await load(await input, imports);

        wasm = instance.exports;
        init.__wbindgen_wasm_module = module;

        return wasm;
    }

    async function main() {
       await init('/pkg/kanidmd_web_ui_bg.wasm');
       run_app();
    }
    main();

}());
