/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package onepasswordsdk implements a provider for 1Password secrets management service.
package onepasswordsdk

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/1password/onepassword-sdk-go"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

type CacheManager struct {
	cache *expirable.LRU[string, []byte]
}

func (c *CacheManager) cacheGet(key string) ([]byte, bool) {
	if c.cache != nil {
		return c.cache.Get(key)
	}
	return nil, false
}

func (c *CacheManager) cacheAdd(key string, value []byte) {
	if c.cache != nil {
		c.cache.Add(key, value)
	}
}

func (c *CacheManager) cacheRemove(key string) {
	if c.cache != nil {
		c.cache.Remove(key)
	}
}

func (c *CacheManager) cacheRemoveByPrefix(prefix string) {
	if c.cache == nil {
		return
	}
	for _, key := range c.cache.Keys() {
		if strings.HasPrefix(key, prefix) {
			c.cache.Remove(key)
		}
	}
}

func (c *CacheManager) GetItem(vault string, item string) (onepassword.Item, bool) {
	if c.cache == nil {
		return onepassword.Item{}, false
	}

	cacheKey := fmt.Sprintf("op:/%s/%s", vault, item)
	if cached, ok := c.cacheGet(cacheKey); ok {
		var cachedItem onepassword.Item
		if err := json.Unmarshal(cached, &cachedItem); err == nil {
			return cachedItem, true
		}
	}
	return onepassword.Item{}, false
}

func (c *CacheManager) AddItem(vault string, item string, value onepassword.Item) {
	if c.cache == nil {
		return
	}

	cacheKey := fmt.Sprintf("op:/%s/%s", vault, item)
	if serialized, err := json.Marshal(value); err == nil {
		c.cacheAdd(cacheKey, serialized)
	}
}

func (c *CacheManager) InvalidateItem(vault string, item string) {
	cacheKey := fmt.Sprintf("op:/%s/%s", vault, item)
	c.cacheRemoveByPrefix(cacheKey)
}

func (c *CacheManager) GetField(vault string, item string, field string) ([]byte, bool) {
	if c.cache == nil {
		return nil, false
	}

	cacheKey := fmt.Sprintf("op:/%s/%s/%s", vault, item, field)
	return c.cacheGet(cacheKey)
}

func (c *CacheManager) AddField(vault string, item string, field string, value []byte) {
	if c.cache == nil {
		return
	}

	cacheKey := fmt.Sprintf("op:/%s/%s/%s", vault, item, field)
	c.cacheAdd(cacheKey, value)
}

func (c *CacheManager) GetFile(vault string, item string, file string) ([]byte, bool) {
	return c.GetField(vault, item, file)
}

func (c *CacheManager) AddFile(vault string, item string, file string, value []byte) {
	c.AddField(vault, item, file, value)
}

func (c *CacheManager) InvalidateField(vault string, item string, field string) {
	cacheKey := fmt.Sprintf("op:/%s/%s/%s", vault, item, field)
	c.cache.Remove(cacheKey)
}

func (c *CacheManager) InvalidateFile(vault string, item string, file string) {
	c.InvalidateField(vault, item, file)
}
