/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import wasilibs "github.com/corazawaf/coraza-wasilibs"

// Only @rx is replaced by RE2. The wasilibs @pm builds its Aho-Corasick
// automaton per rule set without caching, which costs about 70 MB for each
// rule set, so @pm keeps Coraza's memoized Go implementation.
func init() { wasilibs.RegisterRX() }
