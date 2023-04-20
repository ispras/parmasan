#ifndef TRACER_RENAMEAT2_H
#define TRACER_RENAMEAT2_H

#ifndef PARMASAN_RENAMEAT2_HPP
#define PARMASAN_RENAMEAT2_HPP

// For some reason, these are not defined in the stdio for GCC.

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0) /* Don't overwrite target */ // from include/uapi/linux/fs.h
#endif

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1) /* Exchange source and dest */ // from include/uapi/linux/fs.h
#endif

#endif // PARMASAN_RENAMEAT2_HPP

#endif // TRACER_RENAMEAT2_H
