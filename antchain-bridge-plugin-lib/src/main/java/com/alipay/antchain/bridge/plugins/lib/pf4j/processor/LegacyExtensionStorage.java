/*
 * Copyright 2023 Ant Group
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.antchain.bridge.plugins.lib.pf4j.processor;

import com.alipay.antchain.bridge.plugins.lib.BBCService;

import javax.annotation.processing.FilerException;
import javax.tools.FileObject;
import javax.tools.StandardLocation;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Stores {@link BBCService}s in {@code META-INF/extensions.idx}.
 * <p>
 * We modify the code from {@link org.pf4j.processor.LegacyExtensionStorage} to satisfy our needs.
 * </p>
 *
 * @author Decebal Suiu
 */
public class LegacyExtensionStorage extends ExtensionStorage {
    private String storageFile;

    public static final String EXTENSIONS_RESOURCE = "META-INF/extensions.idx";
    public static final String DESCRIPTOR_RESOURCE = "META-INF/descriptor.idx";

    public LegacyExtensionStorage(BBCServiceAnnotationProcessor processor, String file) {
        super(processor);
        storageFile = file;
    }

    @Override
    public Map<String, Set<String>> read() {
        Map<String, Set<String>> extensions = new HashMap<>();

        try {
            FileObject file = getFiler().getResource(StandardLocation.CLASS_OUTPUT, "", storageFile);
            // TODO try to calculate the extension point
            Set<String> entries = new HashSet<>();
            read(file.openReader(true), entries);
            extensions.put(null, entries);
        } catch (FileNotFoundException | NoSuchFileException e) {
            // doesn't exist, ignore
        } catch (FilerException e) {
            // re-opening the file for reading or after writing is ignorable
        } catch (IOException e) {
            error(e.getMessage());
        }

        return extensions;
    }

    @Override
    public void write(Map<String, Set<String>> extensions) {
        try {
            FileObject file = getFiler().createResource(StandardLocation.CLASS_OUTPUT, "", storageFile);
            try (BufferedWriter writer = new BufferedWriter(file.openWriter())) {
                writer.write("# Generated by AntChainBridge"); // write header
                writer.newLine();
                for (Map.Entry<String, Set<String>> entry : extensions.entrySet()) {
                    for (String extension : entry.getValue()) {
                        writer.write(extension);
                        writer.newLine();
                    }
                }
            }
        } catch (FileNotFoundException e) {
            // it's the first time, create the file
        } catch (FilerException e) {
            // re-opening the file for reading or after writing is ignorable
        } catch (IOException e) {
            error(e.toString());
        }
    }

}
