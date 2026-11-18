const _0x1a = require('crypto');
const _0x2b = require('readline');

// Непрозорий предикат (завжди true для цілих чисел)
const _0x3c = (_0x9) => (((_0x9 * _0x9 + _0x9) & 1) === 0);

// Похідний ключ із введеного пароля + статичної солі
const _0x4d = (_0x8) => {
    const _0x7 = Buffer.from([0x19, 0x84, 0x20, 0x26, 0x08, 0x4b, 0x4d]);
    return _0x1a.createHash('sha256').update(Buffer.concat([Buffer.from(_0x8, 'utf8'), _0x7])).digest();
};

// Розшифрування прихованого повідомлення через AES-256-GCM
const _0x5e = (_0x6, _0x5, _0x4, _0x3) => {
    const _0x2 = _0x1a.createDecipheriv('aes-256-gcm', _0x6, Buffer.from(_0x5, 'hex'));
    _0x2.setAuthTag(Buffer.from(_0x4, 'hex'));
    return Buffer.concat([_0x2.update(Buffer.from(_0x3, 'hex')), _0x2.final()]).toString('utf8');
};

const _0x6f = _0x2b.createInterface({ input: process.stdin, output: process.stdout });

_0x6f.question(Buffer.from('d092d0b2d0b5d0b4d196d182d18c20d0bad0bbd18ed18720d0b4d0bed181d182d183d0bfd1833a20', 'hex').toString('utf8'), (_0x7a) => {
    let _0x8b = 0x12 ^ 0x10; // початковий стан = 2
    let _0x9c = {};
    let _0xad = '';

    // Control Flow Flattening (Машина станів)
    while (true) {
        switch (_0x8b) {
            case 0:
                console.log(_0xad);
                _0x6f.close();
                return;
            case 1:
                try {
                    _0xad = _0x5e(_0x9c._k, _0x9c._iv, _0x9c._tg, _0x9c._ct);
                    _0x8b = _0x3c(7) ? 0 : 99;
                } catch (_0xerr) {
                    _0x8b = 4;
                }
                break;
            case 2:
                _0x9c._iv = 'a1b2c3d4e5f60718293a4b5c';
                _0x9c._tg = '8f3e9b1c2d4a6f8091a2b3c4d5e6f708';
                _0x9c._ct = '3c9f1a8b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e';
                _0x8b = 3;
                break;
            case 3:
                _0x9c._k = _0x4d(_0x7a);
                // Перевірка хешу ключа без зберігання самого ключа у відкритому вигляді
                const _0xchk = _0x1a.createHash('sha256').update(_0x9c._k).digest('hex');
                if (_0xchk === _0x1a.createHash('sha256').update(_0x4d("2026_\u041f\u0417-23-1_\u041c\u0430\u0442\u0432\u0456\u0439\u0447\u0443\u043a_\u041a\u0430\u0440\u0456\u043d\u0430_\u0432\u0430\u0440\u0456\u0430\u043d\u0442:08_")).digest('hex')) {
                    _0xad = Buffer.from('d094d0bed181d182d183d0bf20d0b4d0bed0b7d0b2d0bed0bbd0b5d0bdd0be', 'hex').toString('utf8');
                    _0x8b = 0;
                } else {
                    _0x8b = 4;
                }
                break;
            case 4:
                _0xad = Buffer.from('d094d0bed181d182d183d0bf20d0b7d0b0d0b1d0bed180d0bed0bdd0b5d0bdd0be', 'hex').toString('utf8');
                _0x8b = 0;
                break;
            default:
                return;
        }
    }
});