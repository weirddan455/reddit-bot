#include <curl/curl.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_CAPACITY 1048576
#define BOT_USER_AGENT "linux:OP Preserver:v1.0 (by /u/DeeBoFour20)"

struct Buffer {
    size_t size;
    char *data;
};

struct Credentials {
    char id[32];
    char secret[32];
    char username[32];
    char password[32];
};

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct Buffer *buffer = userdata;
    size = size * nmemb;
    if (buffer->size + size >= BUFFER_CAPACITY) {
        puts("Buffer is full");
        return 0;
    }
    memcpy(buffer->data + buffer->size, ptr, size);
    buffer->size += size;
    return size;
}

size_t stub_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    return size * nmemb;
}

static bool read_credentials(struct Credentials *creds)
{
    int fd = open("credentials", O_RDONLY);
    if (fd == -1) {
        perror("read_credentials");
        return false;
    }
    char buffer[128];
    ssize_t bytes = read(fd, buffer, 128);
    if (bytes == -1) {
        perror("read_credentials");
        close(fd);
        return false;
    }
    close(fd);
    int i = 0;
    int j = 0;
    while (buffer[i] != '\r' && buffer[i] != '\n') {
        if (i >= bytes || j >= 31) {
            puts("Malformed credentials file");
            return false;
        }
        creds->id[j] = buffer[i];
        i++;
        j++;
    }
    while (buffer[i] == '\r' || buffer[i] == '\n') {
        i++;
    }
    creds->id[j] = 0;
    j = 0;
    while (buffer[i] != '\r' && buffer[i] != '\n') {
        if (i >= bytes || j >= 31) {
            puts("Malformed credentials file");
            return false;
        }
        creds->secret[j] = buffer[i];
        i++;
        j++;
    }
    while (buffer[i] == '\r' || buffer[i] == '\n') {
        i++;
    }
    creds->secret[j] = 0;
    j = 0;
    while (buffer[i] != '\r' && buffer[i] != '\n') {
        if (i >= bytes || j >= 31) {
            puts("Malformed credentials file");
            return false;
        }
        creds->username[j] = buffer[i];
        i++;
        j++;
    }
    while (buffer[i] == '\r' || buffer[i] == '\n') {
        i++;
    }
    creds->username[j] = 0;
    j = 0;
    while (buffer[i] != '\r' && buffer[i] != '\n' && i < bytes) {
        if (j >= 31) {
            puts("Malformed credentials file");
            return false;
        }
        creds->password[j] = buffer[i];
        i++;
        j++;
    }
    creds->password[j] = 0;
    return true;
}

static struct curl_slist *get_auth_headers(CURL *curl, struct Buffer *buffer, struct Credentials *creds, time_t *auth_expire)
{
    char str[128];
    snprintf(str, 128, "grant_type=password&username=%s&password=%s", creds->username, creds->password);

    buffer->size = 0;
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, BOT_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.reddit.com/api/v1/access_token");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str);
    curl_easy_setopt(curl, CURLOPT_USERNAME, creds->id);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, creds->secret);
    curl_easy_perform(curl);
    buffer->data[buffer->size] = 0;
    char *ptr = strstr(buffer->data, "\"access_token\": ");
    if (ptr == NULL) {
        return NULL;
    }
    ptr += 17;

    const char *auth_constant = "Authorization: Bearer ";
    size_t auth_constant_len = strlen(auth_constant);
    memcpy(str, auth_constant, auth_constant_len);
    char *token = &str[auth_constant_len];

    while (*ptr != '"') {
        *token = *ptr;
        token++;
        ptr++;
    }
    *token = 0;
    ptr++;
    ptr = strstr(ptr, "\"expires_in\": ");
    if (ptr != NULL) {
        ptr += 14;
        long duration = strtol(ptr, NULL, 10);
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        *auth_expire = current_time.tv_sec + duration - 300;
    }
    return curl_slist_append(NULL, str);
}

// Returns a pointer to the end of the dst string
static char *encode_text(char *dst, char *src)
{
    while (*src) {
        if (*src == '&') {
            if (memcmp(src, "&lt;", 4) == 0) {
                memcpy(dst, "%3C", 3);
                dst += 3;
                src += 4;
            } else if (memcmp(src, "&gt;", 4) == 0) {
                memcpy(dst, "%3E", 3);
                dst += 3;
                src += 4;
            } else if (memcmp(src, "&amp;", 5) == 0) {
                memcpy(dst, "%26", 3);
                dst += 3;
                src += 5;
            } else {
                memcpy(dst, "%26", 3);
                dst += 3;
                src += 1;
            }
        } else if (*src == '\\') {
            char escape = *(src + 1);
            switch (escape) {
                case 'n':
                    memcpy(dst, "%0A", 3);
                    dst += 3;
                    src += 2;
                    break;
                case 't':
                    memcpy(dst, "%09", 3);
                    dst += 3;
                    src +=2;
                    break;
                case '"':
                    memcpy(dst, "%22", 3);
                    dst += 3;
                    src += 2;
                    break;
                case '\\':
                    memcpy(dst, "%5C", 3);
                    dst += 3;
                    src += 2;
                    break;
                default:
                    memcpy(dst, "%5C", 3);
                    dst += 3;
                    src += 1;
                    break;
            }
        } else if (*src < '0' || (*src > '9' && *src < 'A') || (*src > 'Z' && *src < 'a') || *src > 'z') {
            sprintf(dst, "%%%02X", *src);
            dst += 3;
            src += 1;
        } else {
            *dst = *src;
            dst += 1;
            src += 1;
        }
    }
    *dst = 0;
    return dst;
}

int main(int argc, char **argv)
{
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        puts("curl_global_init failed");
        return 1;
    }
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        puts("curl_easy_init failed");
        return 1;
    }
    struct Buffer buffer;
    buffer.size = 0;
    buffer.data = malloc(BUFFER_CAPACITY);
    if (buffer.data == NULL) {
        puts("malloc failed");
        return 1;
    }
    char *comment = malloc(BUFFER_CAPACITY);
    if (comment == NULL) {
        puts("malloc failed");
        return 1;
    }
    const char *comment_header = "text="
        "Hello%2C%20I%20am%20a%20bot%20that%20copies%20the%20text%20of%20the%20original%20post%20so%20that%20questions%20and%20their%20answers%20can%20be%20preserved%20to%20benefit%20others%2E%20%20%0A"
        "I%20am%20programmed%20in%20C%20and%20my%20source%20code%20is%20available%20here%3A%20https%3A%2F%2Fgithub%2Ecom%2Fweirddan455%2Freddit%2Dbot%20%20%0A"
        "Please%20message%20my%20owner%20%2Fu%2FDeeBoFour20%20with%20any%20questions%2Fconcerns%2E%20%20%0A"
        "Original%20Post%20by%20%2Fu%2F";
    size_t header_len = strlen(comment_header);
    memcpy(comment, comment_header, header_len);
    char *comment_middle = &comment[header_len];
    const char *line_break = "%20%20%0A%0A---%0A%0A";
    size_t line_break_len = strlen(line_break);
    struct Credentials creds;
    if (!read_credentials(&creds)) {
        puts("Failed to read credentials");
        return 1;
    }

    time_t auth_expire = 0;
    struct curl_slist *headers = get_auth_headers(curl, &buffer, &creds, &auth_expire);
    if (headers == NULL) {
        puts("Failed to get authentication token");
        return 1;
    }

    buffer.size = 0;
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, BOT_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_URL, "https://oauth.reddit.com/r/C_Programming/new.json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_perform(curl);
    buffer.data[buffer.size] = 0;

    char *ptr = strstr(buffer.data, "\"created\": ");
    if (ptr == NULL) {
        puts("Failed to get latest post");
        return 1;
    }
    ptr += 11;
    long last_created = strtol(ptr, NULL, 10);

    if (argc > 1) {
        bool success = false;
        size_t name_len = strlen(argv[1]);
        ptr = buffer.data;
        while ((ptr = strstr(ptr, "\"selftext\": ")) != NULL) {
            ptr += 13;
            char *selftext = ptr;
            while (true) {
                while (*ptr != '"') {
                    ptr++;
                }
                if (*(ptr - 1) == '\\') {
                    ptr++;
                } else {
                    break;
                }
            }
            *ptr = 0;
            ptr++;
            ptr = strstr(ptr, "\"name\": ");
            if (ptr == NULL) {
                break;
            }
            ptr += 9;
            if (memcmp(ptr, argv[1], name_len) == 0) {
                printf("Writing comment for thing_id: %s\n", argv[1]);
                ptr = strstr(ptr, "\"author\": ");
                if (ptr == NULL) {
                    break;
                }
                ptr += 11;
                char *author = ptr;
                size_t author_len = 0;
                while (true) {
                    while (*ptr != '"') {
                        ptr++;
                        author_len++;
                    }
                    if (*(ptr - 1) == '\\') {
                        ptr++;
                        author_len++;
                    } else {
                        break;
                    }
                }
                *ptr = 0;
                memcpy(comment_middle, author, author_len);
                char *comment_ptr = comment_middle + author_len;
                memcpy(comment_ptr, line_break, line_break_len);
                comment_ptr += line_break_len;
                comment_ptr = encode_text(comment_ptr, selftext);
                const char *str = "&thing_id=";
                size_t str_len = strlen(str);
                memcpy(comment_ptr, str, str_len);
                comment_ptr += str_len;
                memcpy(comment_ptr, argv[1], name_len);
                comment_ptr += name_len;
                *comment_ptr = 0;
                curl_easy_reset(curl);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stub_callback);
                curl_easy_setopt(curl, CURLOPT_USERAGENT, BOT_USER_AGENT);
                curl_easy_setopt(curl, CURLOPT_URL, "https://oauth.reddit.com/api/comment");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, comment);
                curl_easy_perform(curl);
                success = true;
                break;
            }
        }
        if (!success) {
            printf("Failed to find thing_id: %s\n", argv[1]);
        }
    }

    while (true) {
        sleep(60);
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        if (current_time.tv_sec >= auth_expire) {
            curl_slist_free_all(headers);
            headers = get_auth_headers(curl, &buffer, &creds, &auth_expire);
            if (headers == NULL) {
                puts("Failed to get authentication token");
                return 1;
            }
        }

        buffer.size = 0;
        curl_easy_reset(curl);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, BOT_USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_URL, "https://oauth.reddit.com/r/C_Programming/new.json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_perform(curl);
        buffer.data[buffer.size] = 0;
        ptr = buffer.data;
        long stop_at = last_created;
        while ((ptr = strstr(ptr, "\"selftext\": ")) != NULL) {
            ptr += 13;
            char *selftext = ptr;
            size_t selftext_len = 0;
            while (true) {
                while (*ptr != '"') {
                    ptr++;
                    selftext_len++;
                }
                if (*(ptr - 1) == '\\') {
                    ptr++;
                    selftext_len++;
                } else {
                    break;
                }
            }
            *ptr = 0;
            ptr++;

            ptr = strstr(ptr, "\"title\": ");
            if (ptr == NULL) {
                break;
            }
            ptr += 10;
            char *title = ptr;
            while (true) {
                while (*ptr != '"') {
                    ptr++;
                }
                if (*(ptr - 1) == '\\') {
                    ptr++;
                } else {
                    break;
                }
            }
            *ptr = 0;
            ptr++;

            ptr = strstr(ptr, "\"name\": ");
            if (ptr == NULL) {
                break;
            }
            ptr += 9;
            char *name = ptr;
            size_t name_len = 0;
            while(*ptr != '"') {
                ptr++;
                name_len++;
            }
            *ptr = 0;
            ptr++;

            ptr = strstr(ptr, "\"created\": ");
            if (ptr == NULL) {
                break;
            }
            ptr += 11;
            long created = strtol(ptr, NULL, 10);
            if (created > last_created) {
                last_created = created;
            }
            if (created <= stop_at) {
                break;
            }

            ptr = strstr(ptr, "\"author\": ");
            if (ptr == NULL) {
                break;
            }
            ptr += 11;
            char *author = ptr;
            size_t author_len = 0;
            while (true) {
                while (*ptr != '"') {
                    ptr++;
                    author_len++;
                }
                if (*(ptr - 1) == '\\') {
                    ptr++;
                    author_len++;
                } else {
                    break;
                }
            }
            *ptr = 0;

            if (selftext_len > 3) {
                sleep(60);
                printf("Writing comment to %s\n", title);
                memcpy(comment_middle, author, author_len);
                char *comment_ptr = comment_middle + author_len;
                memcpy(comment_ptr, line_break, line_break_len);
                comment_ptr += line_break_len;
                comment_ptr = encode_text(comment_ptr, selftext);
                const char *str = "&thing_id=";
                size_t str_len = strlen(str);
                memcpy(comment_ptr, str, str_len);
                comment_ptr += str_len;
                memcpy(comment_ptr, name, name_len);
                comment_ptr += name_len;
                *comment_ptr = 0;
                curl_easy_reset(curl);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stub_callback);
                curl_easy_setopt(curl, CURLOPT_USERAGENT, BOT_USER_AGENT);
                curl_easy_setopt(curl, CURLOPT_URL, "https://oauth.reddit.com/api/comment");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, comment);
                curl_easy_perform(curl);
            }
        }
    }
    return 0;
}
